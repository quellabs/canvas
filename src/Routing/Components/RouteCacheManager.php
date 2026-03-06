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
	 * 1. Checks if cached routes exist
	 * 2. Compares current controller modification times with cached times
	 * 3. Invalidates cache if any controller files changed
	 * 4. Falls back to route rebuilding if cache is stale or missing
	 * 5. Stores new controller modification times alongside routes
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
		private bool $debugMode;
		private array $controllerDirectories;
		private ?int $lastControllerModification = null;
		private int $defaultTtl;
		
		/**
		 * Cache key for storing compiled routes
		 */
		private const string ROUTES_CACHE_KEY = 'compiled_routes';
		
		/**
		 * Cache key for storing controller modification times
		 */
		private const string CONTROLLER_MTIME_KEY = 'controller_modification_time';
		
		/**
		 * RouteCacheManager constructor
		 * @param FileCache $cache
		 * @param bool $debugMode
		 * @param array $controllerDirectories
		 * @param int $defaultTtl
		 */
		public function __construct(
			FileCache $cache,
			bool      $debugMode,
			array     $controllerDirectories,
			int       $defaultTtl = 86400 // 24 hours default
		) {
			$this->cache = $cache;
			$this->debugMode = $debugMode;
			$this->controllerDirectories = $controllerDirectories;
			$this->defaultTtl = $defaultTtl;
		}
		
		/**
		 * Get cached routes if available and valid
		 * @param callable $routeBuilder Callback to build routes if cache miss
		 * @return array Cached or freshly built routes array
		 */
		public function getCachedRoutes(callable $routeBuilder): array {
			// Skip caching entirely in debug mode for development flexibility
			if ($this->debugMode) {
				return $routeBuilder();
			}
			
			// Check if controller files have been modified since last cache
			// This must happen BEFORE trying to retrieve from cache
			if ($this->haveControllersChanged()) {
				// Controllers changed, clear related cache and rebuild
				$this->clearCache();
			}
			
			// Use FileCache remember() for intelligent caching with concurrency protection
			return $this->cache->remember(
				self::ROUTES_CACHE_KEY,
				$this->defaultTtl,
				function () use ($routeBuilder) {
					// Build fresh routes
					$routes = $routeBuilder();
					
					// Cache the current controller modification time
					$this->cacheControllerModificationTime();
					
					// Return the routes
					return $routes;
				}
			);
		}
		
		/**
		 * Check if cache is valid by comparing modification times
		 * @return bool True if cache is still valid, false if stale
		 */
		public function isCacheValid(): bool {
			if ($this->debugMode) {
				return false;
			}
			
			// Check if routes exist in the cache
			if (!$this->cache->has(self::ROUTES_CACHE_KEY)) {
				return false;
			}
			
			// Check if controller modification time has changed
			return !$this->haveControllersChanged();
		}
		
		/**
		 * Clear all cached routes and related data
		 * @return bool True if cache was cleared successfully
		 */
		public function clearCache(): bool {
			$routesCleared = $this->cache->forget(self::ROUTES_CACHE_KEY);
			$mtimeCleared = $this->cache->forget(self::CONTROLLER_MTIME_KEY);
			
			// Reset in-memory cache
			$this->lastControllerModification = null;
			
			return $routesCleared && $mtimeCleared;
		}
		
		/**
		 * Get last modification time of controller files
		 * @return int Unix timestamp of the most recently modified controller file,
		 *             or current time if directories are unconfigured/unreadable (forces cache miss)
		 */
		public function getLastControllerModification(): int {
			// Use cached result if available to avoid expensive filesystem operations
			if ($this->lastControllerModification !== null) {
				return $this->lastControllerModification;
			}

			// If no controller directories present, bail.
			if (empty($this->controllerDirectories)) {
				return $this->lastControllerModification = 0;
			}
			
			// Track the maximum modification time across ALL directories
			$maxTime = 0;
			
			foreach ($this->controllerDirectories as $controllerDirectory) {
				if (!is_dir($controllerDirectory)) {
					// A configured directory that doesn't exist is a deployment/config problem.
					// Force cache invalidation so the issue surfaces immediately rather than
					// serving stale routes silently.
					error_log("RouteCacheManager: Configured controller directory does not exist: {$controllerDirectory}");
					return $this->lastControllerModification = time();
				}
				
				try {
					$iterator = new RecursiveIteratorIterator(
						new RecursiveDirectoryIterator($controllerDirectory, FilesystemIterator::SKIP_DOTS)
					);
					
					foreach ($iterator as $file) {
						if ($file->getExtension() === 'php') {
							$maxTime = max($maxTime, $file->getMTime());
						}
					}
				} catch (\Exception $e) {
					error_log("RouteCacheManager: Error scanning controller directory: {$e->getMessage()}");
					return $this->lastControllerModification = time();
				}
			}
			
			// If $maxTime is still 0, no PHP files exist in any configured directory.
			// Use current time to force a cache miss — an empty controllers set likely
			// means something is wrong, and we don't want to cache that state.
			if ($maxTime === 0) {
				return $this->lastControllerModification = time();
			}
			
			return $this->lastControllerModification = $maxTime;
		}
		
		/**
		 * Check if controller files have been modified since last cache
		 * @return bool True if controllers have changed since last cache
		 */
		private function haveControllersChanged(): bool {
			$currentModificationTime = $this->getLastControllerModification();
			$cachedModificationTime = $this->cache->get(self::CONTROLLER_MTIME_KEY, 0);
			return $currentModificationTime > $cachedModificationTime;
		}
		
		/**
		 * Cache the current controller modification time
		 * @return void True if successfully cached
		 */
		private function cacheControllerModificationTime(): void {
			$currentTime = $this->getLastControllerModification();
			$this->cache->set(self::CONTROLLER_MTIME_KEY, $currentTime, $this->defaultTtl);
		}
	}