<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Components\ControllersDiscovery;
	use Quellabs\Support\ComposerUtils;
	use Symfony\Component\HttpFoundation\Request;
	use Quellabs\Canvas\Cache\Drivers\FileCache;
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Routing\Components\RouteCacheManager;
	use Quellabs\Canvas\Routing\Components\RouteDiscovery;
	use Quellabs\Canvas\Routing\Components\RouteCandidateFilter;
	use Quellabs\Canvas\Routing\Components\RouteMatcher;
	use Quellabs\Canvas\Routing\Components\RoutePatternCompiler;
	use Quellabs\Canvas\Routing\Components\RouteSegmentAnalyzer;
	
	/**
	 * AnnotationResolver
	 *
	 * Main orchestrator for route resolution that coordinates all routing components
	 * to efficiently match incoming HTTP requests to controller actions using
	 * annotation-based route definitions.
	 *
	 * This resolver implements a two-phase matching strategy: aggressive pre-filtering
	 * followed by optimized pattern matching, reducing the computational overhead of
	 * route resolution from O(n) to O(1) + O(k) where n = total routes and k = final
	 * candidates (typically 3-5).
	 *
	 * Architecture and workflow:
	 * 1. Route Discovery: Scans controller classes for @Route annotations
	 * 2. Route Compilation: Pre-compiles route patterns for optimal matching
	 * 3. Index Building: Creates multiple specialized indexes for fast lookups
	 * 4. Request Resolution: Uses pre-filtering + pattern matching for route resolution
	 * 5. Cache Management: Intelligent caching with automatic invalidation
	 *
	 * Pre-filtering pipeline:
	 * - HTTP method filtering: Instant elimination of incompatible methods
	 * - Segment count filtering: Removes routes with wrong path segment counts
	 * - Multi-level static filtering: Compound elimination using static segments at all positions
	 * - Trie-based static lookup: O(k) exact matching for fully static routes
	 * - Compatibility validation: Quick checks before expensive pattern matching
	 *
	 * Component coordination:
	 * - RouteDiscovery: Finds and extracts routes from controller annotations
	 * - RouteCandidateFilter: Builds and queries route indexes to pre-filter candidates before matching
	 * - RouteMatcher: Performs final pattern matching on filtered candidates
	 * - RouteCacheManager: Manages persistent caching with change detection
	 *
	 * Performance characteristics:
	 * - Cold start: Full route discovery and compilation (development/cache miss)
	 * - Warm cache: Near-instant route loading from optimized cache
	 * - Request resolution: 95%+ reduction in routes requiring pattern matching
	 * - Memory efficient: Indexes are built once and reused across requests
	 *
	 * The resolver maintains full backward compatibility while providing significant
	 * performance improvements, especially for applications with large numbers of routes.
     *
	 * @phpstan-import-type RouteDefinition from RouteTypes
	 * @phpstan-import-type RouteIndex from RouteTypes
	 * @phpstan-import-type MatchedRoute from RouteTypes
	 */
	class AnnotationResolver extends AnnotationBase {
		private bool $debugMode;
		private bool $matchTrailingSlashes;
		private string $cacheDirectory;
		
		// Component dependencies
		private RouteMatcher $routeMatcher;
		private RouteCandidateFilter $candidateFilter;
		private RouteDiscovery $routeDiscovery;
		private RouteCacheManager $cacheManager;
		
		/**
		 * Performance optimization cache
		 * @var RouteIndex|null
		 */
		private ?array $routeIndex = null;
		
		/**
		 * AnnotationResolver Constructor
		 * @param Kernel $kernel Application kernel for configuration and services
		 */
		public function __construct(Kernel $kernel) {
			parent::__construct($kernel);
			$this->initializeConfiguration();
			$this->initializeComponents();
			$this->initializeCacheDirectory();
		}
		
		/**
		 * Resolves an HTTP request to find the first matching route
		 * @param Request $request The incoming HTTP request to resolve
		 * @return MatchedRoute Returns the first matched route info
		 * @throws RouteNotFoundException When no matching route is found
		 * @throws AnnotationReaderException On error reading annotations
		 */
		public function resolve(Request $request): array {
			$result = $this->resolveAll($request);
			
			if (!empty($result)) {
				return $result[0];
			}
			
			throw new RouteNotFoundException("Route not found");
		}
		
		/**
		 * Resolves all matching routes using enhanced pre-filtering
		 *
		 * Uses multiple filtering strategies to dramatically reduce the number of routes
		 * that need expensive pattern matching:
		 * 1. HTTP method filtering
		 * 2. Segment count filtering
		 * 3. Multi-level static segment filtering
		 * 4. Prefix trie lookup for static routes
		 *
		 * @param Request $request The HTTP request object
		 * @return list<MatchedRoute> Array of matched route objects, empty if no matches found
		 * @throws AnnotationReaderException
		 */
		public function resolveAll(Request $request): array {
			// Strip query string and decode the path component for consistent matching
			$requestUrl = $this->parseRequestUrl($request->getPathInfo());
			
			// Build the route index or fetch from cache
			$routeIndex = $this->getRouteIndex();
			
			// Pre-filter the full route index to a smaller candidate set based on
			// method and static path segments, avoiding full matching on every route
			$candidates = $this->candidateFilter->getFilteredCandidates(
				$requestUrl,
				$request->getMethod(),
				$routeIndex
			);
			
			$results = [];
			
			foreach ($candidates as $route) {
				// Full match: validates dynamic segments, constraints, and extracts parameters
				// Pass the raw request URI alongside the parsed URL so the matcher has
				// access to the query string if a route requires it
				$match = $this->routeMatcher->matchRoute($route, $requestUrl, $request->getRequestUri(), $request->getMethod());
				
				// Null means the candidate didn't survive full validation; skip it
				if ($match !== null) {
					$results[] = $match;
				}
			}
			
			// Return all matches rather than the first — caller decides priority/ambiguity
			return $results;
		}
		
		/**
		 * Clear all caches and force rebuild
		 * @return bool True if all caches were cleared successfully
		 */
		public function clearAllCaches(): bool {
			$this->routeIndex = null;
			return $this->cacheManager->clearCache();
		}
		
		/**
		 * Parse request URL into segments
		 * @param string $requestUri Raw request URI
		 * @return list<string> Parsed URL segments
		 */
		private function parseRequestUrl(string $requestUri): array {
			$result = [];
			
			foreach (explode('/', $requestUri) as $segment) {
				if ($segment !== '') {
					$result[] = $segment;
				}
			}
			
			return $result;
		}
		
		/**
		 * Get or build route index for fast lookups
		 * @return RouteIndex Complete route index ready for lookups
		 * @throws AnnotationReaderException
		 */
		private function getRouteIndex(): array {
			// Return cached index if available
			if ($this->routeIndex !== null) {
				return $this->routeIndex;
			}
			
			// Get all routes (from cache or fresh build)
			/** @var list<RouteDefinition> $allRoutes */
			$allRoutes = $this->cacheManager->getCachedRoutes(function() {
				return $this->routeDiscovery->buildRoutesFromControllers();
			});
			
			// Build and cache the index
			return $this->routeIndex = $this->candidateFilter->buildRouteIndex($allRoutes);
		}
		
		/**
		 * Initialize configuration from kernel
		 * @return void
		 */
		private function initializeConfiguration(): void {
			$config = $this->kernel->getConfiguration();
			
			$this->debugMode = $config->getAs('debug_mode', 'bool', false);
			$this->matchTrailingSlashes = $config->getAs('match_trailing_slashes', 'bool', false);
			$this->cacheDirectory = $config->get('cache_dir', ComposerUtils::getProjectRoot() . "/storage/cache");
		}
		
		/**
		 * Initialize all routing components with proper dependencies
		 * @return void
		 */
		private function initializeComponents(): void {
			$controllerDiscovery = new ControllersDiscovery($this->kernel);
			
			// Create analyzer for parsing and validating route segments (URL parts)
			$segmentAnalyzer = new RouteSegmentAnalyzer();
			
			// Create compiler to convert route patterns into matchable expressions
			// Depends on segment analyzer for proper URL parsing
			$patternCompiler = new RoutePatternCompiler($segmentAnalyzer);
			
			// Initialize the file-based caching system for storing compiled routes
			// Uses 'routes' as the cache namespace/directory
			$fileCache = new FileCache('routes');
			
			// Set up route matcher to handle incoming request matching
			// Uses instance setting for trailing slash behavior
			$this->routeMatcher = new RouteMatcher($this->matchTrailingSlashes);
			
			// Create index builder for optimizing route lookup performance
			// Requires segment analyzer for proper route categorization
			$this->candidateFilter = new RouteCandidateFilter($segmentAnalyzer);
			
			// Initialize route discovery system to find and register routes
			// Requires kernel for application context, analyzer for parsing,
			// and compiler for pattern compilation
			$this->routeDiscovery = new RouteDiscovery(
				$this->kernel,           // Application kernel instance
				$controllerDiscovery,    // Controller discovery service
				$segmentAnalyzer,        // Route segment parsing service
				$patternCompiler         // Route pattern compilation service
			);
			
			// Set up cache management for storing and retrieving compiled routes
			// Uses file cache for persistence, debug mode affects caching behavior,
			// and controller directory for locating route definitions
			$this->cacheManager = new RouteCacheManager(
				$fileCache,                   // File-based cache storage
				$controllerDiscovery,         // Discovery component
				$this->debugMode,             // Debug mode flag (affects cache invalidation)
			);
		}
		
		/**
		 * Initialize cache directory with proper error handling
		 * @return void
		 */
		private function initializeCacheDirectory(): void {
			if (
				!$this->debugMode &&
				!is_dir($this->cacheDirectory) &&
				!@mkdir($this->cacheDirectory, 0755, true)
			) {
				error_log("AnnotationResolver: Cannot create cache directory: {$this->cacheDirectory}");
				$this->debugMode = true;
			}
		}
	}