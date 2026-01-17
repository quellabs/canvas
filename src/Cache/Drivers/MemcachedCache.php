<?php
	
	namespace Quellabs\Canvas\Cache\Drivers;
	
	use Memcached;
	use Quellabs\Contracts\Cache\CacheInterface;
	
	/**
	 * Memcached-based cache implementation with connection pooling and reliability features
	 *
	 * This implementation provides robust caching using Memcached's distributed architecture:
	 * - Connection pooling with persistent connections for performance
	 * - Multi-server support with consistent hashing
	 * - Automatic failover and retry logic for reliability
	 * - Binary protocol support for improved performance
	 * - Compression support for large values
	 */
	class MemcachedCache implements CacheInterface {
		
		/** @var Memcached Memcached connection instance */
		private Memcached $memcached;
		
		/** @var string Cache context for namespacing */
		private string $namespace;
		
		/** @var int Maximum operation retry attempts */
		private int $maxRetries;
		
		/** @var string Memcached key prefix for this cache instance */
		private string $keyPrefix;
		
		/**
		 * MemcachedCache Constructor
		 * @param string $namespace Cache context for namespacing (e.g., 'pages', 'data')
		 * @param array $config Memcached connection configuration
		 * @param int $maxRetries Maximum operation retry attempts
		 */
		public function __construct(
			string $namespace = 'default',
			array  $config = [],
			int    $maxRetries = 3
		) {
			// Verify memcached extension is available
			$this->checkExtension();
			
			// Store configuration options
			$this->namespace = $namespace;
			$this->maxRetries = $maxRetries;
			$this->keyPrefix = "cache:{$namespace}:";
			
			// Default configuration
			$defaultConfig = [
				'servers'               => [
					['127.0.0.1', 11211, 100] // [host, port, weight]
				],
				'persistent_id'         => null,
				'binary_protocol'       => true,
				'compression'           => true,
				'compression_threshold' => 2000, // bytes
				'serializer'            => Memcached::SERIALIZER_PHP,
				'hash'                  => Memcached::HASH_DEFAULT,
				'distribution'          => Memcached::DISTRIBUTION_CONSISTENT,
				'libketama_compatible'  => true,
				'no_block'              => true,
				'tcp_nodelay'           => true,
				'connect_timeout'       => 2000, // milliseconds
				'poll_timeout'          => 1000,    // milliseconds
				'recv_timeout'          => 750000,  // microseconds
				'send_timeout'          => 750000,  // microseconds
			];
			
			$config = array_merge($defaultConfig, $config);
			$this->initializeMemcachedConnection($config);
		}
		
		/**
		 * Close Memcached connection
		 */
		public function __destruct() {
			if (isset($this->memcached)) {
				// Persistent connections are managed by PHP, but we can quit gracefully
				$this->memcached->quit();
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
				// Build the memcached-compatible key (may add prefixes, sanitize, etc.)
				$memcachedKey = $this->buildKey($key);
				
				// Execute the memcached get operation with retry logic for resilience
				$value = $this->executeWithRetry(function () use ($memcachedKey) {
					return $this->memcached->get($memcachedKey);
				});
				
				// Check for cache miss using getResultCode - this is the proper way to detect
				// if a key doesn't exist (as opposed to checking for false, which could be a valid cached value)
				if ($this->memcached->getResultCode() === Memcached::RES_NOTFOUND) {
					return $default;
				}
				
				// Check for other memcached errors (connection issues, timeouts, etc.)
				// If any error occurred, log it and gracefully fall back to default value
				if ($this->memcached->getResultCode() !== Memcached::RES_SUCCESS) {
					error_log("Memcached get error: " . $this->memcached->getResultMessage());
					return $default;
				}
				
				// Success - return the cached value
				return $value;
				
			} catch (\Exception $e) {
				// Catch any unexpected exceptions (network issues, PHP errors, etc.)
				// Log the error and return default value to prevent application crashes
				error_log("Memcached cache get error: " . $e->getMessage());
				return $default;
			}
		}
		
		/**
		 * Store an item in the cache
		 * @param string $key Cache key
		 * @param mixed $value Value to cache
		 * @param int $ttl Time to live in seconds (0 = forever, max 30 days for Memcached)
		 * @return bool True on success
		 */
		public function set(string $key, mixed $value, int $ttl = 3600): bool {
			try {
				// Build the memcached-compatible key (may add prefixes, sanitize, etc.)
				$memcachedKey = $this->buildKey($key);
				
				// Memcached has a 30-day limit on expiration times when using relative seconds
				// Values > 30 days are treated as Unix timestamps instead of relative seconds
				// Convert large TTL values to absolute Unix timestamp to handle long expirations
				if ($ttl > 2592000) { // 30 days in seconds (60*60*24*30)
					$ttl = time() + $ttl;
				}
				
				// Execute the set operation with retry logic for resilience against transient failures
				return $this->executeWithRetry(function () use ($memcachedKey, $value, $ttl) {
					// Use set() for standard caching behavior (overwrites existing keys)
					$result = $this->memcached->set($memcachedKey, $value, $ttl);
					
					// Log any set failures for debugging - memcached should provide error details
					if (!$result) {
						error_log("Memcached set failed: " . $this->memcached->getResultMessage());
					}
					
					return $result;
				});
				
			} catch (\Exception $e) {
				// Catch any unexpected exceptions (serialization errors, network issues, etc.)
				// Log the error and return false to indicate the cache operation failed
				error_log("Memcached cache set error: " . $e->getMessage());
				return false;
			}
		}
		
		/**
		 * Store an item in the cache (alias for set)
		 * @param string $key Cache key
		 * @param mixed $value Value to cache
		 * @param int $ttl Time to live in seconds (0 = forever, max 30 days)
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
			// Fast path: attempt to retrieve value from cache first
			// This avoids expensive computation if the value is already cached
			$value = $this->get($key);
			
			// Check if we got a cache hit (value exists and is not null)
			// Note: This assumes null is not a valid cached value in your application
			// If null is a valid value, you'd need a different cache miss detection strategy
			if ($value !== null) {
				return $value;
			}
			
			// Cache miss: execute the expensive callback to compute the fresh value
			// This could be a database query, API call, complex calculation, etc.
			$value = $callback();
			
			// Store the computed value in cache for future requests
			// This makes subsequent calls with the same key much faster
			$this->set($key, $value, $ttl);
			
			// Return the computed value to the caller
			return $value;
		}
		
		/**
		 * Remove an item from the cache
		 * @param string $key Cache key
		 * @return bool True if item was removed or didn't exist
		 */
		public function forget(string $key): bool {
			try {
				// Build the memcached-compatible key (consistent with get/set operations)
				$memcachedKey = $this->buildKey($key);
				
				// Execute delete operation with retry logic for resilience
				return $this->executeWithRetry(function () use ($memcachedKey) {
					// Attempt to delete the key from memcached
					$result = $this->memcached->delete($memcachedKey);
					
					// Check the result code to handle different scenarios
					$resultCode = $this->memcached->getResultCode();
					
					// Consider the operation successful if:
					// 1. The delete operation succeeded (key existed and was removed)
					// 2. The key didn't exist in the first place (RES_NOTFOUND)
					// Both scenarios achieve the desired end state: key is not in cache
					return $result || $resultCode === Memcached::RES_NOTFOUND;
				});
				
			} catch (\Exception $e) {
				// Catch any unexpected exceptions (network issues, connection problems, etc.)
				// Log the error and return false to indicate the operation failed
				error_log("Memcached cache forget error: " . $e->getMessage());
				return false;
			}
		}
		
		/**
		 * Clear all items from the cache context
		 * Note: Memcached doesn't support pattern-based deletion, so this flushes everything
		 * @return bool True on success
		 */
		public function flush(): bool {
			try {
				// Execute flush operation with retry logic for resilience against transient failures
				return $this->executeWithRetry(function () {
					// Flush all items from all memcached servers in the pool
					// WARNING: This affects ALL applications using the same memcached instance
					// Consider using key prefixes and versioning for safer cache invalidation
					$result = $this->memcached->flush();
					
					// Log flush failures for debugging - flush operations can fail due to permissions
					// or connectivity issues with memcached servers
					if (!$result) {
						error_log("Memcached flush failed: " . $this->memcached->getResultMessage());
					}
					
					return $result;
				});
				
			} catch (\Exception $e) {
				// Catch any unexpected exceptions (network issues, permission errors, etc.)
				// Log the error and return false to indicate the flush operation failed
				error_log("Memcached cache flush error: " . $e->getMessage());
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
				// Build the memcached-compatible key (consistent with other operations)
				$memcachedKey = $this->buildKey($key);
				
				// Execute existence check with retry logic for resilience
				return $this->executeWithRetry(function () use ($memcachedKey) {
					// Use get() and check result code rather than touch() method
					// This approach is more reliable as touch() can have side effects
					// (it updates the expiration time) and may not be available on all servers
					$this->memcached->get($memcachedKey);
					
					// Check if the get operation was successful (key exists)
					// RES_SUCCESS means the key was found, regardless of its value
					return $this->memcached->getResultCode() === Memcached::RES_SUCCESS;
				});
				
			} catch (\Exception $e) {
				// Catch any unexpected exceptions (network issues, connection problems, etc.)
				// Log the error and return false (assume key doesn't exist) to fail safely
				error_log("Memcached cache has error: " . $e->getMessage());
				return false;
			}
		}
		
		/**
		 * Get cache statistics for monitoring
		 * @return array Cache statistics and server info
		 */
		public function getStats(): array {
			try {
				$stats = $this->executeWithRetry(function () {
					return $this->memcached->getStats();
				});
				
				if (!$stats) {
					return ['error' => 'Failed to retrieve Memcached stats'];
				}
				
				// Aggregate stats from all servers
				$aggregatedStats = [
					'namespace'         => $this->namespace,
					'servers'           => count($stats),
					'total_connections' => 0,
					'total_items'       => 0,
					'total_gets'        => 0,
					'total_sets'        => 0,
					'total_hits'        => 0,
					'total_misses'      => 0,
					'total_memory'      => 0,
					'total_memory_used' => 0,
					'hit_ratio'         => 0.0,
					'servers_detail'    => []
				];
				
				foreach ($stats as $server => $serverStats) {
					if (is_array($serverStats)) {
						$aggregatedStats['total_connections'] += $serverStats['curr_connections'] ?? 0;
						$aggregatedStats['total_items'] += $serverStats['curr_items'] ?? 0;
						$aggregatedStats['total_gets'] += $serverStats['cmd_get'] ?? 0;
						$aggregatedStats['total_sets'] += $serverStats['cmd_set'] ?? 0;
						$aggregatedStats['total_hits'] += $serverStats['get_hits'] ?? 0;
						$aggregatedStats['total_misses'] += $serverStats['get_misses'] ?? 0;
						$aggregatedStats['total_memory'] += $serverStats['limit_maxbytes'] ?? 0;
						$aggregatedStats['total_memory_used'] += $serverStats['bytes'] ?? 0;
						
						$aggregatedStats['servers_detail'][$server] = [
							'uptime'         => $serverStats['uptime'] ?? 0,
							'version'        => $serverStats['version'] ?? 'unknown',
							'curr_items'     => $serverStats['curr_items'] ?? 0,
							'bytes'          => $serverStats['bytes'] ?? 0,
							'limit_maxbytes' => $serverStats['limit_maxbytes'] ?? 0,
						];
					}
				}
				
				// Calculate overall hit ratio
				$totalRequests = $aggregatedStats['total_hits'] + $aggregatedStats['total_misses'];
				
				if ($totalRequests > 0) {
					$aggregatedStats['hit_ratio'] = round(($aggregatedStats['total_hits'] / $totalRequests) * 100, 2);
				}
				
				// Add human-readable memory sizes
				$aggregatedStats['total_memory_human'] = $this->formatBytes($aggregatedStats['total_memory']);
				$aggregatedStats['total_memory_used_human'] = $this->formatBytes($aggregatedStats['total_memory_used']);
				
				return $aggregatedStats;
				
			} catch (\Exception $e) {
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
		 * Check if memcached extension and class are available
		 * @throws \RuntimeException If memcached extension is not available
		 */
		private function checkExtension(): void {
			// Check if memcached extension is loaded
			if (!extension_loaded('memcached')) {
				throw new \RuntimeException(
					'The memcached PHP extension is required but not installed. ' .
					'Please install php-memcached extension or use a different cache driver.'
				);
			}
			
			// Check if Memcached class is available (additional safety check)
			if (!class_exists('Memcached')) {
				throw new \RuntimeException(
					'Memcached class is not available. Please ensure the memcached extension is properly loaded.'
				);
			}
		}
		
		/**
		 * Initialize Memcached connection with configuration
		 * @param array $config Memcached configuration
		 * @throws \RuntimeException If connection fails
		 */
		private function initializeMemcachedConnection(array $config): void {
			// Use persistent connection if persistent_id is provided
			$this->memcached = new Memcached($config['persistent_id'] ?? null);
			
			// Only add servers if this is a new persistent connection or non-persistent
			if (empty($this->memcached->getServerList())) {
				// Add servers
				foreach ($config['servers'] as $server) {
					$host = $server[0];
					$port = $server[1] ?? 11211;
					$weight = $server[2] ?? 100;
					
					if (!$this->memcached->addServer($host, $port, $weight)) {
						throw new \RuntimeException("Failed to add Memcached server: {$host}:{$port}");
					}
				}
			}
			
			// Set options
			$options = [
				Memcached::OPT_BINARY_PROTOCOL      => $config['binary_protocol'],
				Memcached::OPT_COMPRESSION          => $config['compression'],
				Memcached::OPT_SERIALIZER           => $config['serializer'],
				Memcached::OPT_HASH                 => $config['hash'],
				Memcached::OPT_DISTRIBUTION         => $config['distribution'],
				Memcached::OPT_LIBKETAMA_COMPATIBLE => $config['libketama_compatible'],
				Memcached::OPT_NO_BLOCK             => $config['no_block'],
				Memcached::OPT_TCP_NODELAY          => $config['tcp_nodelay'],
				Memcached::OPT_CONNECT_TIMEOUT      => $config['connect_timeout'],
				Memcached::OPT_POLL_TIMEOUT         => $config['poll_timeout'],
				Memcached::OPT_RECV_TIMEOUT         => $config['recv_timeout'],
				Memcached::OPT_SEND_TIMEOUT         => $config['send_timeout'],
			];
			
			foreach ($options as $option => $value) {
				if (!$this->memcached->setOption($option, $value)) {
					error_log("Failed to set Memcached option: {$option}");
				}
			}
			
			// Test connection
			$version = $this->memcached->getVersion();
			if ($version === false) {
				throw new \RuntimeException("Failed to connect to Memcached servers");
			}
		}
		
		/**
		 * Build the full Memcached key for a cache key
		 * @param string $key Cache key
		 * @return string Full Memcached key with namespace prefix
		 */
		private function buildKey(string $key): string {
			// Memcached keys have length and character restrictions
			// Use SHA-256 hash to ensure consistent, valid keys
			$hashedKey = hash('sha256', $key);
			$fullKey = $this->keyPrefix . $hashedKey;
			
			// Memcached key length limit is 250 characters
			if (strlen($fullKey) > 250) {
				return hash('sha256', $fullKey);
			}
			
			return $fullKey;
		}
		
		/**
		 * Execute Memcached operation with retry logic
		 * @param callable $operation Memcached operation to execute
		 * @return mixed Operation result
		 * @throws \Exception If all retries fail
		 */
		private function executeWithRetry(callable $operation): mixed {
			$attempts = 0;
			$lastException = null;
			
			// Retry loop - continue until max retries reached or operation succeeds
			while ($attempts < $this->maxRetries) {
				try {
					// Execute the memcached operation (get, set, delete, etc.)
					$result = $operation();
					
					// Check the result code to determine if the operation was successful
					// or encountered an error that we should handle
					$resultCode = $this->memcached->getResultCode();
					
					// These result codes indicate successful operations or expected states:
					// - RES_SUCCESS: Operation completed successfully
					// - RES_NOTFOUND: Key doesn't exist (expected for get operations on missing keys)
					// - RES_NOTSTORED: Key wasn't stored (expected for add operations on existing keys)
					if ($resultCode === Memcached::RES_SUCCESS ||
						$resultCode === Memcached::RES_NOTFOUND ||
						$resultCode === Memcached::RES_NOTSTORED) {
						return $result;
					}
					
					// Check if this is a recoverable error that we should retry
					// Examples: connection timeouts, temporary server unavailability, network issues
					if ($this->isRecoverableError($resultCode)) {
						// Throw exception to trigger retry logic with backoff
						throw new \Exception("Memcached error: " . $this->memcached->getResultMessage());
					}
					
					// Non-recoverable error (e.g., invalid arguments, protocol errors)
					// Return the result immediately without retrying as these won't be fixed by retrying
					return $result;
					
				} catch (\Exception $e) {
					// Store the exception in case we need to re-throw after all retries fail
					$lastException = $e;
					$attempts++;
					
					// If we haven't exhausted all retries, wait before the next attempt
					if ($attempts < $this->maxRetries) {
						// Exponential backoff: wait 100ms, then 200ms, then 400ms, etc.
						// This reduces load on memcached servers and increases chance of recovery
						// Formula: 100ms * 2^(attempts-1) = 100ms, 200ms, 400ms, 800ms...
						usleep(100000 * pow(2, $attempts - 1));
					}
				}
			}
			
			// All retries exhausted - re-throw the last exception encountered
			// Preserve the original exception chain for debugging purposes
			throw new \Exception($lastException->getMessage(), $lastException->getCode(), $lastException);
		}
		
		/**
		 * Check if a Memcached error code is recoverable
		 * @param int $resultCode Memcached result code
		 * @return bool True if error might be recoverable with retry
		 */
		private function isRecoverableError(int $resultCode): bool {
			$recoverableErrors = [
				Memcached::RES_CONNECTION_SOCKET_CREATE_FAILURE,
				Memcached::RES_ERRNO,
				Memcached::RES_HOST_LOOKUP_FAILURE,
				Memcached::RES_NO_SERVERS,
				Memcached::RES_SERVER_ERROR,
				Memcached::RES_SERVER_TEMPORARILY_DISABLED,
				Memcached::RES_TIMEOUT,
				Memcached::RES_WRITE_FAILURE,
				Memcached::RES_READ_FAILURE,
			];
			
			return in_array($resultCode, $recoverableErrors);
		}
		
		/**
		 * Format bytes into human-readable format
		 * @param int $bytes Number of bytes
		 * @return string Formatted string (e.g., "1.5 MB")
		 */
		private function formatBytes(int $bytes): string {
			$units = ['B', 'KB', 'MB', 'GB', 'TB'];
			$factor = floor((strlen($bytes) - 1) / 3);
			
			return sprintf("%.2f %s", $bytes / pow(1024, $factor), $units[$factor]);
		}
	}