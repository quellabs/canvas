<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	use Quellabs\Canvas\Exceptions\RateLimitStoreUnavailableException;
	use Redis;
	use RedisException;

	/**
	 * Redis-backed rate limit store. Each admission is one Lua script executed
	 * with EVAL, so the read, the decision, and the write happen as a single
	 * atomic step on Redis's single-threaded command execution - no PHP-side
	 * locking is needed, unlike FileRateLimitStore/MemcachedRateLimitStore.
	 *
	 * The math mirrors RateLimitMath's admission logic, but implemented in Lua
	 * since it must run server-side to be atomic; RateLimitMath isn't reused
	 * here. One difference: the sliding-window sorted set has no equivalent of
	 * RateLimitMath's tracked-timestamp cap, so its entry count under sustained
	 * abuse is unbounded within the window.
	 */
	class RedisRateLimitStore implements RateLimitStoreInterface {

		private const string FIXED_WINDOW_SCRIPT = <<<'LUA'
			local count = redis.call('INCR', KEYS[1])
			if count == 1 then
				redis.call('EXPIRE', KEYS[1], ARGV[1])
			end
			return count
			LUA;

		private const string SLIDING_WINDOW_SCRIPT = <<<'LUA'
			local key = KEYS[1]
			local cutoff = ARGV[1]
			local now = ARGV[2]
			local window = ARGV[3]
			local limit = tonumber(ARGV[4])
			redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
			local seq = redis.call('INCR', key .. ':seq')
			redis.call('ZADD', key, now, now .. '-' .. seq)
			redis.call('EXPIRE', key, window)
			redis.call('EXPIRE', key .. ':seq', window)
			local count = redis.call('ZCARD', key)
			-- When the limit is exceeded, retrying before enough of the *oldest*
			-- entries expire still leaves the window full - report the timestamp of
			-- the entry whose expiry actually frees a slot, not just the single
			-- oldest one.
			local target = now
			if count > limit then
				local idx = count - limit
				local entries = redis.call('ZRANGE', key, idx, idx, 'WITHSCORES')
				if entries[2] ~= nil then
					target = entries[2]
				end
			end
			return {count, target}
			LUA;

		private const string TOKEN_BUCKET_SCRIPT = <<<'LUA'
			local key = KEYS[1]
			local limit = tonumber(ARGV[1])
			local refillRate = tonumber(ARGV[2])
			local now = tonumber(ARGV[3])
			local ttl = ARGV[4]
			local data = redis.call('HMGET', key, 'tokens', 'last_refill')
			local tokens = tonumber(data[1])
			local lastRefill = tonumber(data[2])
			if tokens == nil then
				tokens = limit
				lastRefill = now
			end
			local elapsed = now - lastRefill
			if elapsed < 0 then
				elapsed = 0
			end
			tokens = math.min(limit, tokens + elapsed * refillRate)
			local exceeded = 0
			if tokens < 1 then
				exceeded = 1
			else
				tokens = tokens - 1
			end
			redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
			redis.call('EXPIRE', key, ttl)
			return {exceeded, tostring(tokens)}
			LUA;

		/** @var Redis Redis connection instance */
		private Redis $redis;

		/** @var string Redis key prefix for this store */
		private string $keyPrefix;

		/** @var int Maximum connection retry attempts */
		private int $maxRetries;

		/**
		 * Constructor
		 * @param array<string, mixed> $config Redis connection configuration
		 */
		public function __construct(array $config = []) {
			$this->checkExtension();
			$this->keyPrefix = 'rate_limit:';

			$maxRetries = $config['max_retries'] ?? 3;
			$this->maxRetries = is_int($maxRetries) && $maxRetries > 0 ? $maxRetries : 3;

			$default = [
				'host'         => '127.0.0.1',
				'port'         => 6379,
				'timeout'      => 2.5,
				'read_timeout' => 2.5,
				'database'     => 0,
				'password'     => null,
			];

			$this->initializeConnection(array_merge($default, $config));
		}

		/**
		 * Close Redis connection
		 * @return void
		 */
		public function __destruct() {
			try {
				$this->redis->close();
			} catch (RedisException) {
				// Ignore cleanup errors
			}
		}

		/**
		 * @inheritDoc
		 */
		public function incrementFixedWindow(string $key, int $limit, int $window, int $now): RateLimitResult {
			$windowStart = intdiv($now, $window) * $window;
			$resetTime = $windowStart + $window;
			$redisKey = $this->buildKey($key . ':fixed:' . $windowStart);

			$raw = $this->eval(self::FIXED_WINDOW_SCRIPT, [$redisKey], [$window]);

			if (!is_numeric($raw)) {
				throw new RateLimitStoreUnavailableException('Redis fixed-window script returned an unexpected result');
			}

			$count = (int)$raw;

			return new RateLimitResult(
				$count,
				$count > $limit,
				$resetTime,
				max(0, $resetTime - $now)
			);
		}

		/**
		 * @inheritDoc
		 */
		public function admitSlidingWindow(string $key, int $limit, int $window, int $now): RateLimitResult {
			$redisKey = $this->buildKey($key . ':sliding');
			$cutoff = $now - $window;

			$raw = $this->eval(self::SLIDING_WINDOW_SCRIPT, [$redisKey], [$cutoff, $now, $window, $limit]);

			if (!is_array($raw) || count($raw) !== 2 || !is_numeric($raw[0]) || !is_numeric($raw[1])) {
				throw new RateLimitStoreUnavailableException('Redis sliding-window script returned an unexpected result');
			}

			$count = (int)$raw[0];
			$target = (int)$raw[1];
			$exceeded = $count > $limit;

			return new RateLimitResult(
				$count,
				$exceeded,
				$now + $window,
				$exceeded ? max(0, ($target + $window) - $now) : 0
			);
		}

		/**
		 * @inheritDoc
		 */
		public function admitTokenBucket(string $key, int $limit, int $window, int $now): RateLimitResult {
			$redisKey = $this->buildKey($key . ':bucket');
			$refillRate = $window > 0 ? $limit / $window : (float)$limit;

			$raw = $this->eval(self::TOKEN_BUCKET_SCRIPT, [$redisKey], [$limit, $refillRate, $now, $window * 2]);

			if (!is_array($raw) || count($raw) !== 2 || !is_numeric($raw[0]) || !is_numeric($raw[1])) {
				throw new RateLimitStoreUnavailableException('Redis token-bucket script returned an unexpected result');
			}

			$exceeded = (int)$raw[0] === 1;
			$tokens = (float)$raw[1];
			$retryAfter = $exceeded && $refillRate > 0 ? (int)ceil((1 - $tokens) / $refillRate) : 0;

			return new RateLimitResult(
				(int)($limit - floor($tokens)),
				$exceeded,
				$now + $retryAfter,
				$retryAfter
			);
		}

		/**
		 * Execute a Lua script with retry-on-connection-error, raising
		 * RateLimitStoreUnavailableException instead of ever fabricating a result.
		 * @param string $script
		 * @param list<string> $keys
		 * @param list<int|float|string> $args
		 * @return mixed
		 */
		private function eval(string $script, array $keys, array $args): mixed {
			$attempts = 0;

			while (true) {
				try {
					$result = $this->redis->eval($script, [...$keys, ...$args], count($keys));

					if ($result === false) {
						$error = $this->redis->getLastError();

						if ($error !== null) {
							$this->redis->clearLastError();
							throw new RateLimitStoreUnavailableException("Redis rate limit script error: {$error}");
						}
					}

					return $result;
				} catch (RedisException $e) {
					$attempts++;

					if ($attempts >= $this->maxRetries) {
						throw new RateLimitStoreUnavailableException(
							'Redis rate limit store error: ' . $e->getMessage(),
							503,
							$e
						);
					}

					usleep(100000 * (2 ** ($attempts - 1)));

					try {
						$this->redis->ping();
					} catch (RedisException) {
						// Still broken; the next loop iteration will retry or exhaust attempts.
					}
				}
			}
		}

		/**
		 * Build the full Redis key for a rate limit key
		 * @param string $key
		 * @return string
		 */
		private function buildKey(string $key): string {
			return $this->keyPrefix . hash('sha256', $key);
		}

		/**
		 * Check if redis extension and class are available
		 * @return void
		 * @throws RateLimitStoreUnavailableException If redis extension is not available
		 */
		private function checkExtension(): void {
			if (!extension_loaded('redis') || !class_exists('Redis')) {
				throw new RateLimitStoreUnavailableException(
					'The redis PHP extension is required but not installed. ' .
					'Please install php-redis or use a different rate limit store driver.'
				);
			}
		}

		/**
		 * Initialize the Redis connection with the given configuration
		 * @param array<string, mixed> $config
		 * @return void
		 * @throws RateLimitStoreUnavailableException If connection fails
		 */
		private function initializeConnection(array $config): void {
			$this->redis = new Redis();

			try {
				$host = is_string($config['host']) ? $config['host'] : '127.0.0.1';
				$port = is_int($config['port']) ? $config['port'] : 6379;
				$timeout = is_float($config['timeout']) || is_int($config['timeout']) ? (float)$config['timeout'] : 2.5;
				$readTimeout = is_float($config['read_timeout']) || is_int($config['read_timeout']) ? (float)$config['read_timeout'] : 2.5;
				$database = is_int($config['database']) ? $config['database'] : 0;
				$password = is_string($config['password']) ? $config['password'] : null;

				$connected = $this->redis->connect($host, $port, $timeout, null, 0, $readTimeout);

				if (!$connected) {
					throw new RateLimitStoreUnavailableException('Failed to connect to Redis server');
				}

				if ($password !== null && $password !== '' && !$this->redis->auth($password)) {
					throw new RateLimitStoreUnavailableException('Redis authentication failed');
				}

				if ($database > 0 && !$this->redis->select($database)) {
					throw new RateLimitStoreUnavailableException('Failed to select Redis database');
				}

				$this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_NONE);
			} catch (RedisException $e) {
				throw new RateLimitStoreUnavailableException('Redis connection failed: ' . $e->getMessage(), 503, $e);
			}
		}
	}
