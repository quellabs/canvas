<?php
	
	namespace Quellabs\Canvas\Cache\Drivers;
	
	use Redis;
	use RedisException;
	use Quellabs\Contracts\Cache\CacheInterface;
	
	/**
	 * Redis-based cache implementation leveraging Redis's atomic operations
	 *
	 * This implementation provides thread-safe caching using Redis's natural atomicity:
	 * - Single-threaded Redis eliminates most concurrency concerns
	 * - Atomic operations for complex scenarios (remember method)
	 * - Native TTL support with automatic expiration
	 * - Connection pooling and retry logic for reliability
	 */
	class RedisCache implements CacheInterface {
		
		/** @var Redis Redis connection instance */
		private Redis $redis;
		
		/** @var string Cache context for namespacing */
		private string $namespace;
		
		/** @var int Maximum connection retry attempts */
		private int $maxRetries;
		
		/** @var string Redis key prefix for this cache instance */
		private string $keyPrefix;
		
		/**
		 * RedisCache Constructor
		 * @param string $namespace Cache context for namespacing (e.g., 'pages', 'data')
		 * @param array $config Redis connection configuration
		 * @param int $maxRetries Maximum connection retry attempts
		 * @throws \RuntimeException If redis extension is not available
		 */
		public function __construct(
			string $namespace = 'default',
			array  $config = [],
			int    $maxRetries = 3
		) {
			// Verify redis extension is available
			$this->checkExtension();
			
			// Store configuration options
			$this->namespace = $namespace;
			$this->maxRetries = $maxRetries;
			$this->keyPrefix = "cache:{$namespace}:";
			
			// Initialize Redis connection with default config
			$defaultConfig = [
				'host'         => '127.0.0.1',
				'port'         => 6379,
				'timeout'      => 2.5,
				'read_timeout' => 2.5,
				'database'     => 0,
				'password'     => null,
			];
			
			$config = array_merge($defaultConfig, $config);
			
			$this->initializeRedisConnection($config);
		}
		
		/**
		 * Close Redis connection
		 */
		public function __destruct() {
			if (isset($this->redis)) {
				try {
					$this->redis->close();
				} catch (RedisException $e) {
					// Ignore cleanup errors
				}
			}
		}
		
		/**
		 * Get an item from the cache
		 * @param string $key Cache key
		 * @param mixed $default Default value if key doesn't exist
		 * @return mixed The cached value or default
		 */
		public function get(string $key, mixed $default = null): mixed {
			try {
				// Build the key to fetch
				$redisKey = $this->buildKey($key);
				
				// Redis GET is atomic - no locking needed
				$data = $this->executeWithRetry(function () use ($redisKey) {
					return $this->redis->get($redisKey);
				});
				
				// Handle cache miss
				if ($data === false) {
					return $default;
				}
				
				// Unserialize the data
				$value = @unserialize($data);
				
				// Invalid data, clean up
				if ($value === false) {
					$this->forget($key);
					return $default;
				}
				
				// Return the data
				return $value;
				
			} catch (\Exception $e) {
				error_log("Redis cache get error: " . $e->getMessage());
				return $default;
			}
		}
		
		/**
		 * Store an item in the cache
		 * @param string $key Cache key
		 * @param mixed $value Value to cache
		 * @param int $ttl Time to live in seconds (0 = forever)
		 * @return bool True on success
		 */
		public function set(string $key, mixed $value, int $ttl = 3600): bool {
			try {
				$redisKey = $this->buildKey($key);
				$serializedData = serialize($value);
				
				return $this->executeWithRetry(function () use ($redisKey, $serializedData, $ttl) {
					// SET without expiration
					if ($ttl == 0) {
						return $this->redis->set($redisKey, $serializedData);
					}
					
					// SETEX is atomic - sets value and TTL in one operation
					return $this->redis->setex($redisKey, $ttl, $serializedData);
				});
				
			} catch (\Exception $e) {
				error_log("Redis cache set error: " . $e->getMessage());
				return false;
			}
		}
		
		/**
		 * Store an item in the cache (alias for set)
		 * @param string $key Cache key
		 * @param mixed $value Value to cache
		 * @param int $ttl Time to live in seconds (0 = forever)
		 * @return bool True on success
		 */
		public function put(string $key, mixed $value, int $ttl = 3600): bool {
			return $this->set($key, $value, $ttl);
		}
		
		/**
		 * Get an item or execute callback and store result
		 * @param string $key Cache key
		 * @param int $ttl Time to live in seconds
		 * @param callable $callback Callback to execute on cache miss
		 * @return mixed The cached or computed value
		 */
		public function remember(string $key, int $ttl, callable $callback): mixed {
			// Fast path: check if value already exists in cache
			// This avoids expensive callback execution in most cases
			$value = $this->get($key);
			
			if ($value !== null) {
				return $value;
			}
			
			// Execute the expensive callback to compute the value
			$value = $callback();
			
			// Store the computed value in cache for future requests
			$this->set($key, $value, $ttl);
			
			// Return the freshly computed value to the caller
			// This ensures the caller gets the result regardless of cache state
			return $value;
		}
		
		/**
		 * This method deletes a specific key from Redis. It's safe to call
		 * even if the key doesn't exist - Redis DEL command is idempotent.
		 * @param string $key Cache key
		 * @return bool True if item was removed or didn't exist
		 */
		public function forget(string $key): bool {
			try {
				// Convert the user-provided key to the namespaced Redis key
				// This ensures we're targeting the correct key in our namespace
				$redisKey = $this->buildKey($key);
				
				return $this->executeWithRetry(function () use ($redisKey) {
					// Execute Redis DEL command
					$this->redis->del($redisKey);
					return true;
				});
				
			} catch (\Exception $e) {
				// Log the error for debugging but don't throw
				// This allows the application to continue running even if Redis is down
				error_log("Redis cache forget error: " . $e->getMessage());
				
				// Return false to indicate the operation couldn't be completed
				// The caller can decide how to handle this failure
				return false;
			}
		}
		
		/**
		 * Clear all items from the cache context
		 * @return bool True on success
		 */
		public function flush(): bool {
			try {
				// Use SCAN for memory efficiency with large keysets
				// This is safer than KEYS * on production systems
				return $this->executeWithRetry(function () {
					$iterator = null;
					$pattern = $this->keyPrefix . "*";
					
					do {
						$keys = $this->redis->scan($iterator, $pattern, 100);
						
						if (!empty($keys)) {
							$this->redis->del($keys);
						}
					} while ($iterator > 0);
					
					return true;
				});
				
			} catch (\Exception $e) {
				error_log("Redis cache flush error: " . $e->getMessage());
				return false;
			}
		}
		
		/**
		 * Check if an item exists in the cache
		 * @param string $key Cache key
		 * @return bool True if key exists
		 */
		public function has(string $key): bool {
			try {
				$redisKey = $this->buildKey($key);
				
				return $this->executeWithRetry(function () use ($redisKey) {
					return $this->redis->exists($redisKey) > 0;
				});
				
			} catch (\Exception $e) {
				error_log("Redis cache has error: " . $e->getMessage());
				return false;
			}
		}
		
		/**
		 * Get namespace-specific statistics for monitoring
		 * @return array Namespace stats and general Redis info
		 */
		public function getStats(): array {
			try {
				// Get general Redis server information
				$info = $this->executeWithRetry(function () {
					return $this->redis->info();
				});
				
				// Count keys in this specific namespace using SCAN
				// This is more efficient than KEYS * for large datasets
				$namespaceKeyCount = $this->executeWithRetry(function () {
					$iterator = null;
					$pattern = $this->keyPrefix . "*";
					$count = 0;
					
					// Use SCAN to iterate through keys matching our namespace pattern
					// SCAN is non-blocking and memory-efficient for production use
					do {
						// Get up to 100 keys per iteration
						$keys = $this->redis->scan($iterator, $pattern, 100);
						if ($keys !== false) {
							// Add the number of keys found in this batch
							$count += count($keys);
						}
						// Continue until the iterator returns to 0 (scan complete)
					} while ($iterator > 0);
					
					return $count;
				});
				
				return [
					'namespace'         => $this->namespace,                   // Current cache namespace
					'namespace_keys'    => $namespaceKeyCount,                 // Keys in this namespace only
					'connected_clients' => $info['connected_clients'] ?? 0,    // Total Redis clients
					'used_memory'       => $info['used_memory'] ?? 0,          // Redis memory usage (bytes)
					'used_memory_human' => $info['used_memory_human'] ?? '0B', // Human-readable memory usage
					'keyspace_hits'     => $info['keyspace_hits'] ?? 0,        // Total cache hits across all Redis
					'keyspace_misses'   => $info['keyspace_misses'] ?? 0,      // Total cache misses across all Redis
					'hit_ratio'         => $this->calculateHitRatio($info),    // Cache hit percentage
				];
				
			} catch (\Exception $e) {
				// Return error info instead of throwing exception
				// This allows monitoring systems to handle Redis unavailability gracefully
				return ['error' => $e->getMessage()];
			}
		}
		
		/**
		 * Get the current namespace
		 * @return string Current namespace
		 */
		public function getNamespace(): string {
			return $this->namespace;
		}
		
		/**
		 * Check if redis extension and class are available
		 * @throws \RuntimeException If redis extension is not available
		 */
		private function checkExtension(): void {
			// Check if redis extension is loaded
			if (!extension_loaded('redis')) {
				throw new \RuntimeException(
					'The redis PHP extension is required but not installed. ' .
					'Please install php-redis extension or use a different cache driver.'
				);
			}
			
			// Check if Redis class is available (additional safety check)
			if (!class_exists('Redis')) {
				throw new \RuntimeException(
					'Redis class is not available. Please ensure the redis extension is properly loaded.'
				);
			}
		}
		
		/**
		 * Initialize Redis connection with configuration
		 * @param array $config Redis configuration
		 * @throws \RuntimeException If connection fails
		 */
		private function initializeRedisConnection(array $config): void {
			$this->redis = new Redis();
			
			try {
				// Connect to Redis
				$connected = $this->redis->connect(
					$config['host'],
					$config['port'],
					$config['timeout'],
					null,
					0,
					$config['read_timeout']
				);
				
				if (!$connected) {
					throw new \RuntimeException("Failed to connect to Redis server");
				}
				
				// Authenticate if password is provided
				if (!empty($config['password'])) {
					if (!$this->redis->auth($config['password'])) {
						throw new \RuntimeException("Redis authentication failed");
					}
				}
				
				// Select database
				if ($config['database'] > 0) {
					if (!$this->redis->select($config['database'])) {
						throw new \RuntimeException("Failed to select Redis database");
					}
				}
				
				// Don't use automatic serialization - we handle it manually for consistency
				$this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_NONE);
				
			} catch (RedisException $e) {
				throw new \RuntimeException("Redis connection failed: " . $e->getMessage());
			}
		}
		
		/**
		 * Build the full Redis key for a cache key
		 * @param string $key Cache key
		 * @return string Full Redis key with namespace prefix
		 */
		private function buildKey(string $key): string {
			return $this->keyPrefix . hash('sha256', $key);
		}
		
		/**
		 * Execute Redis operation with retry logic
		 * @param callable $operation Redis operation to execute
		 * @return mixed Operation result
		 * @throws \Exception
		 */
		private function executeWithRetry(callable $operation): mixed {
			$attempts = 0;
			$lastException = null;
			
			// Keep trying until we reach the maximum retry limit
			while ($attempts < $this->maxRetries) {
				try {
					// Attempt to execute the Redis operation
					return $operation();
				} catch (RedisException $e) {
					// Store the exception in case this is the final attempt
					$lastException = $e;
					$attempts++;
					
					// If we haven't exhausted all retries, wait and try to reconnect
					if ($attempts < $this->maxRetries) {
						// Exponential backoff: 100ms, 200ms, 400ms...
						// This prevents overwhelming a struggling Redis server
						usleep(100000 * pow(2, $attempts - 1));
						
						// Attempt to reconnect to Redis
						try {
							$this->redis->ping();
						} catch (RedisException $reconnectException) {
							// The connection is still broken, but we'll try the operation again
							// The next retry attempt will either succeed or fail again
						}
					}
				}
			}
			
			// All retry attempts have been exhausted
			// Re-throw the last exception so the caller knows what went wrong
			throw new \Exception($lastException->getMessage(), $lastException->getCode(), $lastException);
		}
		
		/**
		 * Calculate the cache hit ratio from Redis stats
		 * @param array $info Redis info array
		 * @return float Hit ratio as percentage
		 */
		private function calculateHitRatio(array $info): float {
			$hits = $info['keyspace_hits'] ?? 0;
			$misses = $info['keyspace_misses'] ?? 0;
			$total = $hits + $misses;
			
			return $total > 0 ? round(($hits / $total) * 100, 2) : 0.0;
		}
	}