<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	use Memcached;
	use Random\RandomException;
	use Quellabs\Canvas\Exceptions\RateLimitStoreUnavailableException;

	/**
	 * Memcached-backed rate limit store. Memcached has no server-side scripting,
	 * so atomicity is achieved client-side with compare-and-swap (CAS) and bounded
	 * retries: read the current state together with its CAS token, compute the
	 * new state with RateLimitMath, then write it back only if nothing else wrote
	 * to that key since the read. A concurrent writer in between makes the CAS
	 * write fail, and the loop retries against the now-current state - it never
	 * blindly overwrites with the result of a stale read.
	 */
	class MemcachedRateLimitStore implements RateLimitStoreInterface {

		/** @var Memcached Memcached connection instance */
		private Memcached $memcached;

		/** @var string Memcached key prefix for this store */
		private string $keyPrefix;

		/** @var int Maximum CAS retry attempts before giving up on a key */
		private int $maxCasRetries;

		/**
		 * Constructor
		 * @param array<string, mixed> $config Memcached connection configuration
		 */
		public function __construct(array $config = []) {
			$this->checkExtension();
			$this->keyPrefix = 'rate_limit:';

			$maxCasRetries = $config['max_cas_retries'] ?? 10;
			$this->maxCasRetries = is_int($maxCasRetries) && $maxCasRetries > 0 ? $maxCasRetries : 10;

			$default = [
				'servers'       => [['127.0.0.1', 11211, 100]],
				'persistent_id' => null,
			];

			$this->initializeConnection(array_merge($default, $config));
		}

		/**
		 * @inheritDoc
		 */
		public function incrementFixedWindow(string $key, int $limit, int $window, int $now): RateLimitResult {
			$cacheKey = $this->buildKey($key . ':fixed:' . intdiv($now, $window) * $window);

			return $this->casUpdate(
				$cacheKey,
				$window,
				fn(?array $state) => RateLimitMath::fixedWindow($state, $limit, $window, $now)
			);
		}

		/**
		 * @inheritDoc
		 */
		public function admitSlidingWindow(string $key, int $limit, int $window, int $now): RateLimitResult {
			$cacheKey = $this->buildKey($key . ':sliding');

			return $this->casUpdate(
				$cacheKey,
				$window,
				fn(?array $state) => RateLimitMath::slidingWindow($state, $limit, $window, $now)
			);
		}

		/**
		 * @inheritDoc
		 */
		public function admitTokenBucket(string $key, int $limit, int $window, int $now): RateLimitResult {
			$cacheKey = $this->buildKey($key . ':bucket');

			return $this->casUpdate(
				$cacheKey,
				$window * 2,
				fn(?array $state) => RateLimitMath::tokenBucket($state, $limit, $window, $now)
			);
		}
		
		/**
		 * Read the current state and its CAS token, compute the next state via $compute,
		 * and write it back only if the key hasn't changed since the read. Retries against
		 * the freshly-read state on a CAS conflict, up to maxCasRetries.
		 * @param string $cacheKey
		 * @param int $ttl
		 * @param callable(array<string, mixed>|null): RateLimitAdmission $compute
		 * @return RateLimitResult
		 * @throws RateLimitStoreUnavailableException
		 * @throws RandomException
		 */
		private function casUpdate(string $cacheKey, int $ttl, callable $compute): RateLimitResult {
			for ($attempt = 0; $attempt < $this->maxCasRetries; $attempt++) {
				$existing = $this->memcached->get($cacheKey, null, Memcached::GET_EXTENDED);
				$resultCode = $this->memcached->getResultCode();

				if ($resultCode === Memcached::RES_NOTFOUND) {
					$state = null;
					$casToken = null;
				} elseif ($resultCode === Memcached::RES_SUCCESS && is_array($existing)) {
					$rawValue = $existing['value'] ?? null;

					// This store never caches a null value, so a null read-back is corrupt or foreign data, not a fresh key - treating it as fresh could reset the counter or refill a bucket.
					if ($rawValue === null || ($state = $this->asStringKeyedArray($rawValue)) === null) {
						throw new RateLimitStoreUnavailableException(
							"Memcached rate limit cache entry for key '{$cacheKey}' contains corrupt or unexpected data"
						);
					}

					$casToken = $existing['cas'] ?? null;
				} else {
					throw new RateLimitStoreUnavailableException(
						'Memcached rate limit read error: ' . $this->memcached->getResultMessage()
					);
				}

				$admission = $compute($state);

				if ($casToken === null) {
					// No existing value: add() fails if another process created it first,
					// which is exactly the signal to retry against that process's value.
					if ($this->memcached->add($cacheKey, $admission->getState(), $ttl)) {
						return $admission->getResult();
					}
				} elseif (is_float($casToken) || is_int($casToken)) {
					if ($this->memcached->cas((float)$casToken, $cacheKey, $admission->getState(), $ttl)) {
						return $admission->getResult();
					}
				}

				// Lost the race: another process wrote first. Back off briefly and retry
				// against whatever is there now, rather than overwriting it.
				usleep(random_int(1000, 5000));
			}

			throw new RateLimitStoreUnavailableException(
				"Rate limit CAS update for key '{$cacheKey}' did not converge after {$this->maxCasRetries} attempts"
			);
		}

		/**
		 * Validates that $data is an array keyed entirely by strings, as the state
		 * this class itself caches always is. A cached value is untrusted - data from
		 * a corrupted or foreign-format cache entry is treated as no state at all
		 * rather than passed through with an unverified key type.
		 * @param mixed $data
		 * @return array<string, mixed>|null
		 */
		private function asStringKeyedArray(mixed $data): ?array {
			if (!is_array($data)) {
				return null;
			}

			$result = [];

			foreach ($data as $key => $value) {
				if (!is_string($key)) {
					return null;
				}

				$result[$key] = $value;
			}

			return $result;
		}

		/**
		 * Build the full Memcached key for a rate limit key
		 * @param string $key
		 * @return string
		 */
		private function buildKey(string $key): string {
			$fullKey = $this->keyPrefix . hash('sha256', $key);
			return strlen($fullKey) > 250 ? hash('sha256', $fullKey) : $fullKey;
		}

		/**
		 * Check if the memcached extension and class are available
		 * @return void
		 * @throws RateLimitStoreUnavailableException If the memcached extension is not available
		 */
		private function checkExtension(): void {
			if (!extension_loaded('memcached') || !class_exists('Memcached')) {
				throw new RateLimitStoreUnavailableException(
					'The memcached PHP extension is required but not installed. ' .
					'Please install php-memcached or use a different rate limit store driver.'
				);
			}
		}

		/**
		 * Initialize the Memcached connection with the given configuration
		 * @param array<string, mixed> $config
		 * @return void
		 * @throws RateLimitStoreUnavailableException If connection fails
		 */
		private function initializeConnection(array $config): void {
			$persistentId = $config['persistent_id'] ?? null;
			
			if (is_string($persistentId) && $persistentId !== '') {
				$this->memcached = new Memcached($persistentId);
			} else {
				$this->memcached = new Memcached();
			}

			if (empty($this->memcached->getServerList())) {
				$servers = is_array($config['servers']) ? $config['servers'] : [];

				foreach ($servers as $server) {
					if (!is_array($server) || !isset($server[0]) || !is_string($server[0])) {
						continue;
					}

					$host = $server[0];
					$port = isset($server[1]) && is_int($server[1]) ? $server[1] : 11211;
					$weight = isset($server[2]) && is_int($server[2]) ? $server[2] : 100;

					if (!$this->memcached->addServer($host, $port, $weight)) {
						throw new RateLimitStoreUnavailableException("Failed to add Memcached server: {$host}:{$port}");
					}
				}
			}

			$this->memcached->setOption(Memcached::OPT_BINARY_PROTOCOL, true);

			if ($this->memcached->getVersion() === false) {
				throw new RateLimitStoreUnavailableException('Failed to connect to Memcached servers');
			}
		}
	}
