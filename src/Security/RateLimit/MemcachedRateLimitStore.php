<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	use Memcached;
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
		 * @param callable(array<mixed, mixed>|null): array{0: array<string, mixed>, 1: RateLimitResult} $compute
		 * @return RateLimitResult
		 * @throws RateLimitStoreUnavailableException
		 */
		private function casUpdate(string $cacheKey, int $ttl, callable $compute): RateLimitResult {
			for ($attempt = 0; $attempt < $this->maxCasRetries; $attempt++) {
				$existing = $this->memcached->get($cacheKey, null, Memcached::GET_EXTENDED);
				$resultCode = $this->memcached->getResultCode();

				if ($resultCode === Memcached::RES_NOTFOUND) {
					$state = null;
					$casToken = null;
				} elseif ($resultCode === Memcached::RES_SUCCESS && is_array($existing)) {
					$value = $existing['value'] ?? null;
					$state = is_array($value) ? $value : null;
					$casToken = $existing['cas'] ?? null;
				} else {
					throw new RateLimitStoreUnavailableException(
						'Memcached rate limit read error: ' . $this->memcached->getResultMessage()
					);
				}

				[$newState, $result] = $compute($state);

				if ($casToken === null) {
					// No existing value: add() fails if another process created it first,
					// which is exactly the signal to retry against that process's value.
					if ($this->memcached->add($cacheKey, $newState, $ttl)) {
						return $result;
					}
				} elseif (is_float($casToken) || is_int($casToken)) {
					if ($this->memcached->cas((float)$casToken, $cacheKey, $newState, $ttl)) {
						return $result;
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
		 * @throws RateLimitStoreUnavailableException If connection fails
		 */
		private function initializeConnection(array $config): void {
			$persistentId = $config['persistent_id'] ?? null;

			$this->memcached = is_string($persistentId) && $persistentId !== ''
				? new Memcached($persistentId)
				: new Memcached();

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
