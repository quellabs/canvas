<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Cache\Foundation\FileCache;
	use Symfony\Component\HttpFoundation\Request;
	
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
		private RouteSegmentAnalyzer $segmentAnalyzer;
		private RoutePatternCompiler $patternCompiler;
		private RouteMatcher $routeMatcher;
		private RouteIndexBuilder $indexBuilder;
		private RouteDiscovery $routeDiscovery;
		private RouteCacheManager $cacheManager;
		
		// Performance optimization cache
		private array $routeIndex = [];
		
		/**
		 * AnnotationResolver Constructor
		 *
		 * Initializes all routing components and establishes their dependencies.
		 * The dependency injection pattern makes the system testable and modular.
		 *
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
		 * Resolves an HTTP request to find all matching routes
		 *
		 * This method implements the complete resolution pipeline:
		 * 1. Parse and cache request URL
		 * 2. Get route index (with caching)
		 * 3. Try static routes first (O(1) lookup)
		 * 4. Try dynamic routes (filtered search)
		 * 5. Try wildcard routes (last resort)
		 *
		 * @param Request $request The incoming HTTP request to resolve
		 * @return array Returns all matched route info or empty array if no matches
		 */
		public function resolveAll(Request $request): array {
			$requestUrl = $this->parseRequestUrl($request->getRequestUri());
			$requestMethod = $request->getMethod();
			$originalUrl = $request->getRequestUri();
			$routeIndex = $this->getRouteIndex();
			
			// Define route matching function for reusability
			$matchRoutes = function (array $routes) use ($requestUrl, $originalUrl, $requestMethod) {
				return array_values(array_filter(
					array_map(
						fn($route) => $this->routeMatcher->matchRoute($route, $requestUrl, $originalUrl, $requestMethod),
						$routes
					)
				));
			};
			
			// Try static routes first (fastest lookup)
			$firstSegment = $requestUrl[0] ?? '';
			
			if (isset($routeIndex['static'][$firstSegment])) {
				$result = $matchRoutes($routeIndex['static'][$firstSegment]);
				
				if (!empty($result)) {
					return $result;
				}
			}
			
			// Try dynamic routes (filtered by priority)
			if (!empty($routeIndex['dynamic'])) {
				$result = $matchRoutes($routeIndex['dynamic']);
				
				if (!empty($result)) {
					return $result;
				}
			}
			
			// Try wildcard routes (last resort)
			return $matchRoutes($routeIndex['wildcard'] ?? []);
		}
		
		/**
		 * Get comprehensive routing statistics for debugging
		 *
		 * This method provides detailed information about the routing system
		 * state, which is invaluable for debugging and performance analysis.
		 *
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
		 *
		 * This method clears all internal caches and forces a complete rebuild
		 * of the routing system. Useful during development or deployment.
		 *
		 * @return bool True if all caches were cleared successfully
		 */
		public function clearAllCaches(): bool {
			$this->routeIndex = [];
			
			$this->indexBuilder->clearIndex();
			$this->routeDiscovery->clearReflectionCache();
			
			return $this->cacheManager->clearCache();
		}
		
		/**
		 * Warm up all caches for optimal performance
		 *
		 * This method pre-builds all caches and indexes, which is useful
		 * for deployment scenarios where you want to eliminate cold start penalties.
		 *
		 * @return bool True if cache warming succeeded
		 */
		public function warmCaches(): bool {
			try {
				// Build fresh routes and cache them
				$routes = $this->fetchAllRoutesOptimized();
				
				// Build route index
				$this->routeIndex = $this->indexBuilder->buildRouteIndex($routes);
				
				// Warm route cache
				return $this->cacheManager->warmCache($routes);
				
			} catch (\Exception $e) {
				error_log("AnnotationResolver: Cache warming failed: " . $e->getMessage());
				return false;
			}
		}
		
		/**
		 * Parse request URL into segments
		 *
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
		 *
		 * This method coordinates between the index builder and cache manager
		 * to provide the most efficient route lookup structure possible.
		 *
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
			$this->routeIndex = $this->indexBuilder->buildRouteIndex($allRoutes);
			
			return $this->routeIndex;
		}
		
		/**
		 * Fetch all routes using optimized caching strategy
		 *
		 * This method coordinates with the cache manager to implement
		 * an intelligent caching strategy that balances performance
		 * with cache freshness.
		 *
		 * @return array All compiled routes ready for matching
		 */
		private function fetchAllRoutesOptimized(): array {
			return $this->cacheManager->getCachedRoutes(function () {
				return $this->routeDiscovery->buildRoutesFromControllers();
			});
		}
		
		/**
		 * Initialize configuration from kernel
		 *
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
		 *
		 * @return void
		 */
		private function initializeComponents(): void {
			// Initialize core analyzers and compilers
			$this->segmentAnalyzer = new RouteSegmentAnalyzer();
			$this->patternCompiler = new RoutePatternCompiler($this->segmentAnalyzer);
			
			// Initialize matcher with configuration
			$this->routeMatcher = new RouteMatcher($this->matchTrailingSlashes);
			
			// Initialize indexing and discovery services
			$this->indexBuilder = new RouteIndexBuilder($this->segmentAnalyzer);
			$this->routeDiscovery = new RouteDiscovery(
				$this->kernel,
				$this->segmentAnalyzer,
				$this->patternCompiler
			);
			
			// Initialize cache manager with file cache
			$fileCache = new FileCache($this->cacheDirectory, 'routes');
			$this->cacheManager = new RouteCacheManager(
				$fileCache,
				$this->debugMode,
				$this->controllerDirectory
			);
		}
		
		/**
		 * Initialize cache directory with proper error handling
		 *
		 * @return void
		 */
		private function initializeCacheDirectory(): void {
			if (!$this->debugMode && !is_dir($this->cacheDirectory)) {
				if (!@mkdir($this->cacheDirectory, 0755, true)) {
					error_log("AnnotationResolver: Cannot create cache directory: {$this->cacheDirectory}");
					// Fall back to debug mode if caching fails
					$this->debugMode = true;
				}
			}
		}
		
		/**
		 * Get the absolute path to the controllers directory
		 *
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