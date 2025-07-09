<?php
	
	namespace Quellabs\Canvas\Cache\Contracts;
	
	interface CacheInterface {
		
		/**
		 * Get an item from the cache
		 * @param string $key Cache key
		 * @param mixed $default Default value if key doesn't exist
		 * @return mixed The cached value or default
		 */
		public function get(string $key, mixed $default = null): mixed;
		
		/**
		 * Store an item in the cache
		 * @param string $key Cache key
		 * @param mixed $value Value to cache
		 * @param int $ttl Time to live in seconds (0 = forever)
		 * @return bool True on success
		 */
		public function set(string $key, mixed $value, int $ttl = 3600): bool;
		
		/**
		 * Get an item or execute callback and store result
		 * @param string $key Cache key
		 * @param int $ttl Time to live in seconds
		 * @param callable $callback Callback to execute if cache miss
		 * @return mixed The cached or computed value
		 */
		public function remember(string $key, int $ttl, callable $callback): mixed;
		
		/**
		 * Remove an item from the cache
		 * @param string $key Cache key
		 * @return bool True if item was removed
		 */
		public function forget(string $key): bool;
		
		/**
		 * Clear all items from the cache
		 * @return bool True on success
		 */
		public function flush(): bool;
		
		/**
		 * Check if an item exists in the cache
		 * @param string $key Cache key
		 * @return bool True if key exists and hasn't expired
		 */
		public function has(string $key): bool;
	}