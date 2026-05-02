<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use FilesystemIterator;
	use RecursiveDirectoryIterator;
	use RecursiveIteratorIterator;
	use Quellabs\Canvas\Cache\Drivers\FileCache;
	
	/**
	 * RouteCacheManager
	 *
	 * Manages route caching and optimization using the FileCache system to provide
	 * persistent storage of compiled routes with intelligent cache invalidation based
	 * on controller file modifications.
	 *
	 * Core responsibilities:
	 * - Route caching: Stores compiled routes and indexes to avoid expensive rebuilds
	 * - Cache invalidation: Automatically detects controller file changes
	 * - File modification tracking: Monitors controller directory for updates
	 * - Debug mode handling: Bypasses caching during development
	 * - Concurrency protection: Uses FileCache atomic operations for thread safety
	 * - Cache statistics: Provides metrics on cache performance and status
	 *
	 * Caching strategy:
	 * - Production mode: Aggressive caching with file modification detection
	 * - Debug mode: Cache bypass for immediate reflection of code changes
	 * - Intelligent invalidation: Compares controller modification times
	 * - Atomic operations: Thread-safe cache updates using FileCache
	 * - Configurable TTL: Default 24-hour cache lifetime with override support
	 *
	 * Cache validation process:
	 * 1. Checks if cached routes exist (including embedded mtime)
	 * 2. Compares current controller modification times with cached times
	 * 3. Invalidates cache if any controller files changed
	 * 4. Falls back to route rebuilding if cache is stale or missing
	 * 5. Stores new controller modification times atomically alongside routes
	 *
	 * File monitoring:
	 * - Recursive directory scanning for PHP files
	 * - Modification time tracking for cache invalidation
	 * - Error handling for filesystem access issues
	 * - Graceful degradation when file scanning fails
	 *
	 * Performance impact:
	 * - Cache hits: Near-instant route loading (microseconds)
	 * - Cache misses: Full route discovery and compilation (milliseconds)
	 * - File monitoring: Lightweight timestamp comparisons
	 * - Memory efficiency: Routes loaded once per application lifecycle
	 *
	 * The cache manager ensures optimal performance in production while maintaining
	 * development-friendly behavior with automatic cache invalidation when controllers
	 * are modified.
	 */
	class RouteCacheManager {
		
		private FileCache $cache;
		private ControllersDiscovery $controllersDiscovery;
		private bool $debugMode;
		private int $defaultTtl;
		
		/**
		 * Cache key for storing compiled routes bundled with their mtime snapshot.
		 * Structure: ['mtime' => int, 'routes' => array]
		 * Bundling both values in one key makes reads and writes atomic,
		 * eliminating the race window that existed when they were stored separately.
		 */
		private const string ROUTES_CACHE_KEY = 'compiled_routes';
		
		/**
		 * RouteCacheManager constructor
		 * @param FileCache $cache
		 * @param ControllersDiscovery $controllersDiscovery
		 * @param bool $debugMode
		 * @param int $defaultTtl
		 */
		public function __construct(
			FileCache $cache,
			ControllersDiscovery $controllersDiscovery,
			bool      $debugMode,
			int       $defaultTtl = 86400 // 24 hours default
		) {
			$this->cache = $cache;
			$this->controllersDiscovery = $controllersDiscovery;
			$this->debugMode = $debugMode;
			$this->defaultTtl = $defaultTtl;
		}
		
		/**
		 * Get cached routes if available and valid, rebuilding if stale or missing.
		 * @template T
		 * @param callable(): T $builder Callback to build routes if cache miss
		 * @return T Cached or freshly built routes array
		 */
		public function getCachedRoutes(callable $builder): mixed {
			// Skip caching entirely in debug mode for development flexibility
			if ($this->debugMode) {
				return $builder();
			}
			
			$currentMtime = $this->getLastControllerModification();
			$cached = $this->cache->get(self::ROUTES_CACHE_KEY);
			
			// Cache hit: entry exists and mtime still matches
			if (
				$cached !== null &&
				isset($cached['mtime'], $cached['routes']) &&
				$cached['mtime'] === $currentMtime
			) {
				return $cached['routes'];
			}
			
			// Cache miss or stale: rebuild and store atomically
			$routes = $builder();
			
			$this->cache->set(
				self::ROUTES_CACHE_KEY,
				['mtime' => $currentMtime, 'routes' => $routes],
				$this->defaultTtl
			);
			
			return $routes;
		}
		
		/**
		 * Check if cache is valid by comparing modification times.
		 * Pure read — no filesystem side effects beyond what getLastControllerModification
		 * already documents.
		 * @return bool True if cache is still valid, false if stale
		 */
		public function isCacheValid(): bool {
			if ($this->debugMode) {
				return false;
			}
			
			$cached = $this->cache->get(self::ROUTES_CACHE_KEY);
			
			if ($cached === null || !isset($cached['mtime'], $cached['routes'])) {
				return false;
			}
			
			return $cached['mtime'] === $this->getLastControllerModification();
		}
		
		/**
		 * Clear all cached routes and related data
		 * @return bool True if cache was cleared successfully
		 */
		public function clearCache(): bool {
			return $this->cache->forget(self::ROUTES_CACHE_KEY);
		}
		
		/**
		 * Get last modification time of controller files.
		 * Always performs a fresh filesystem scan — no in-memory caching —
		 * so long-running processes (PHP-FPM workers) always see current state.
		 * @return int Unix timestamp of the most recently modified controller file,
		 *             or current time if directories are unconfigured/unreadable (forces cache miss)
		 */
		public function getLastControllerModification(): int {
			// Fetch the controller directories
			$controllerClasses = $this->controllersDiscovery->fetch();
			
			// If no controller directories present, bail.
			if (empty($controllerClasses)) {
				return 0;
			}
			
			// Track the maximum modification time across ALL directories
			$maxTime = 0;
			
			foreach ($controllerClasses as $className) {
				try {
					$file = (new \ReflectionClass($className))->getFileName();
					
					if ($file !== false) {
						$maxTime = max($maxTime, filemtime($file));
					}
				} catch (\ReflectionException $e) {
					error_log("RouteCacheManager: Cannot reflect controller class {$className}: {$e->getMessage()}");
					return time();
				}
			}
			
			// If $maxTime is still 0, no PHP files exist in any configured directory.
			// Use current time to force a cache miss — an empty controllers set likely
			// means something is wrong, and we don't want to cache that state.
			return $maxTime === 0 ? time() : $maxTime;
		}
	}