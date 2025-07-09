<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\Canvas\Kernel;
	use Symfony\Component\HttpFoundation\Request;
	use Quellabs\Canvas\Cache\Foundation\FileCache;
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Routing\Components\RouteCacheManager;
	use Quellabs\Canvas\Routing\Components\RouteDiscovery;
	use Quellabs\Canvas\Routing\Components\RouteIndexBuilder;
	use Quellabs\Canvas\Routing\Components\RouteMatcher;
	use Quellabs\Canvas\Routing\Components\RoutePatternCompiler;
	use Quellabs\Canvas\Routing\Components\RouteSegmentAnalyzer;
	
	/**
	 * AnnotationResolver (Refactored)
	 *
	 * Main orchestrator class for route resolution that coordinates all routing components.
	 * This refactored version delegates specific responsibilities to focused classes while
	 * providing the same public API as the original implementation.
	 *
	 * Components:
	 * - RouteSegmentAnalyzer: Analyzes and classifies route segments
	 * - RoutePatternCompiler: Compiles route patterns for optimization
	 * - RouteMatcher: Handles URL matching against compiled routes
	 * - RouteIndexBuilder: Builds indexes for fast route lookups
	 * - RouteDiscovery: Discovers routes from controller classes
	 * - RouteCacheManager: Manages route caching and optimization
	 */
	class AnnotationResolver extends AnnotationBase {
		private Kernel $kernel;
		private bool $debugMode;
		private bool $matchTrailingSlashes;
		private string $cacheDirectory;
		private string $controllerDirectory;
		
		// Component dependencies
		private RouteMatcher $routeMatcher;
		private RouteIndexBuilder $indexBuilder;
		private RouteDiscovery $routeDiscovery;
		private RouteCacheManager $cacheManager;
		
		// Performance optimization cache
		private array $routeIndex = [];
		
		/**
		 * AnnotationResolver Constructor
		 * @param Kernel $kernel Application kernel for configuration and services
		 */
		public function __construct(Kernel $kernel) {
			parent::__construct($kernel->getAnnotationsReader());
			
			$this->kernel = $kernel;
			$this->initializeConfiguration();
			$this->initializeComponents();
			$this->initializeCacheDirectory();
		}
		
		/**
		 * Resolves an HTTP request to find the first matching route
		 * @param Request $request The incoming HTTP request to resolve
		 * @return array Returns the first matched route info
		 * @throws RouteNotFoundException When no matching route is found
		 */
		public function resolve(Request $request): array {
			$result = $this->resolveAll($request);
			
			if (!empty($result)) {
				return $result[0];
			}
			
			throw new RouteNotFoundException("Route not found");
		}
		
		/**
		 * Resolves all matching routes for a given HTTP request using a tiered matching strategy.
		 * Tries static routes first, then dynamic routes, then wildcard routes as fallback.
		 * @param Request $request The HTTP request object
		 * @return array Array of matched route objects, empty if no matches found
		 */
		public function resolveAll(Request $request): array {
			$requestUrl = $this->parseRequestUrl($request->getRequestUri());
			$routeIndex = $this->getRouteIndex();
			
			// Helper function to match routes and filter out nulls
			$matchRoutes = fn(array $routes) => array_values(array_filter(
				array_map(
					fn($route) => $this->routeMatcher->matchRoute($route, $requestUrl, $request->getRequestUri(), $request->getMethod()),
					$routes
				)
			));
			
			// Try static routes first (fastest lookup)
			$firstSegment = $requestUrl[0] ?? '';
			
			if (isset($routeIndex['static'][$firstSegment])) {
				if ($result = $matchRoutes($routeIndex['static'][$firstSegment])) {
					return $result;
				}
			}
			
			// Try dynamic routes, then wildcard routes
			foreach (['dynamic', 'wildcard'] as $type) {
				if (!empty($routeIndex[$type]) && $result = $matchRoutes($routeIndex[$type])) {
					return $result;
				}
			}
			
			return [];
		}
		
		/**
		 * Get comprehensive routing statistics for debugging
		 * @return array Comprehensive routing statistics
		 */
		public function getRoutingStatistics(): array {
			return [
				'configuration' => [
					'debug_mode'             => $this->debugMode,
					'match_trailing_slashes' => $this->matchTrailingSlashes,
					'cache_directory'        => $this->cacheDirectory,
					'controller_directory'   => $this->controllerDirectory
				],
				'cache'         => $this->cacheManager->getCacheInfo(),
				'discovery'     => $this->routeDiscovery->getDiscoveryStatistics(),
				'index'         => $this->indexBuilder->getIndexStatistics(),
				'performance'   => [
					'route_index_built' => !empty($this->routeIndex)
				]
			];
		}
		
		/**
		 * Clear all caches and force rebuild
		 * @return bool True if all caches were cleared successfully
		 */
		public function clearAllCaches(): bool {
			$this->routeIndex = [];
			$this->indexBuilder->clearIndex();
			$this->routeDiscovery->clearReflectionCache();
			return $this->cacheManager->clearCache();
		}
		
		/**
		 * Parse request URL into segments
		 * @param string $requestUri Raw request URI
		 * @return array Parsed URL segments
		 */
		private function parseRequestUrl(string $requestUri): array {
			// Parse URL into segments
			return array_values(array_filter(
				explode('/', $requestUri),
				fn($segment) => $segment !== ''
			));
		}
		
		/**
		 * Get or build route index for fast lookups
		 * @return array Complete route index ready for lookups
		 */
		private function getRouteIndex(): array {
			// Return cached index if available
			if (!empty($this->routeIndex)) {
				return $this->routeIndex;
			}
			
			// Get all routes (from cache or fresh build)
			$allRoutes = $this->fetchAllRoutesOptimized();
			
			// Build and cache the index
			return $this->routeIndex = $this->indexBuilder->buildRouteIndex($allRoutes);
		}
		
		/**
		 * Fetch all routes using optimized caching strategy
		 * @return array All compiled routes ready for matching
		 */
		private function fetchAllRoutesOptimized(): array {
			return $this->cacheManager->getCachedRoutes(function () {
				return $this->routeDiscovery->buildRoutesFromControllers();
			});
		}
		
		/**
		 * Initialize configuration from kernel
		 * @return void
		 */
		private function initializeConfiguration(): void {
			$config = $this->kernel->getConfiguration();
			
			$this->debugMode = $config->getAs('debug_mode', 'bool', false);
			$this->matchTrailingSlashes = $config->getAs('match_trailing_slashes', 'bool', false);
			$this->cacheDirectory = $config->get('cache_dir', $this->kernel->getDiscover()->getProjectRoot() . "/storage/cache");
			$this->controllerDirectory = $this->getControllerDirectory();
		}
		
		/**
		 * Initialize all routing components with proper dependencies
		 * Sets up the complete routing system including analyzers, matchers,
		 * indexing services, and cache management
		 * @return void
		 */
		private function initializeComponents(): void {
			// Initialize core analyzers and compilers
			// RouteSegmentAnalyzer breaks down route patterns into analyzable segments
			$segmentAnalyzer = new RouteSegmentAnalyzer();
			
			// RoutePatternCompiler converts route patterns into matchable expressions
			// Depends on segment analyzer for proper pattern parsing
			$patternCompiler = new RoutePatternCompiler($segmentAnalyzer);
			
			// Initialize matcher with configuration
			// RouteMatcher handles the actual matching of incoming requests to routes
			// matchTrailingSlashes determines if /path/ and /path should be treated as equivalent
			$this->routeMatcher = new RouteMatcher($this->matchTrailingSlashes);
			
			// Initialize indexing and discovery services
			// RouteIndexBuilder creates optimized indexes for faster route lookups
			// Uses segment analyzer to understand route structure for efficient indexing
			$this->indexBuilder = new RouteIndexBuilder($segmentAnalyzer);
			
			// RouteDiscovery automatically finds and registers routes from controllers
			// Requires kernel for dependency injection, analyzer for route parsing,
			// and compiler for converting discovered routes into usable patterns
			$this->routeDiscovery = new RouteDiscovery(
				$this->kernel,           // Application kernel for DI container access
				$segmentAnalyzer,        // Analyzes route segments during discovery
				$patternCompiler         // Compiles discovered routes into patterns
			);
			
			// Initialize cache manager with file cache
			// FileCache provides persistent storage for compiled routes
			// Uses specified cache directory and 'routes' namespace for organization
			$fileCache = new FileCache($this->cacheDirectory, 'routes');
			
			// RouteCacheManager coordinates caching of compiled routes and indexes
			// In debug mode, cache is bypassed or frequently invalidated
			// Controller directory is monitored for changes to invalidate cache
			$this->cacheManager = new RouteCacheManager(
				$fileCache,              // File-based cache storage implementation
				$this->debugMode,        // Debug flag affects cache behavior
				$this->controllerDirectory // Directory to watch for controller changes
			);
		}
		
		/**
		 * Initialize cache directory with proper error handling
		 * @return void
		 */
		private function initializeCacheDirectory(): void {
			// Only attempt to create cache directory if debug mode is disabled
			// and the directory doesn't already exist
			if (!$this->debugMode && !is_dir($this->cacheDirectory)) {
				// Use @ to suppress warnings and handle errors manually
				// Create directory with 0755 permissions (rwxr-xr-x)
				// The 'true' parameter creates parent directories recursively
				if (!@mkdir($this->cacheDirectory, 0755, true)) {
					// Log the error for debugging purposes
					error_log("AnnotationResolver: Cannot create cache directory: {$this->cacheDirectory}");
					
					// Fall back to debug mode if caching fails
					// This ensures the application continues to function even without caching
					$this->debugMode = true;
				}
			}
		}
		
		/**
		 * Get the absolute path to the controllers directory
		 * @return string Absolute path to controllers directory
		 */
		private function getControllerDirectory(): string {
			$projectRoot = $this->kernel->getDiscover()->getProjectRoot();
			$fullPath = $projectRoot . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "Controllers";
			
			if (!is_dir($fullPath)) {
				return "";
			}
			
			return realpath($fullPath) ?: "";
		}
	}