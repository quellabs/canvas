<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	/**
	 * RouteIndexBuilder
	 *
	 * Builds and manages route indexes for fast lookups during request resolution.
	 * This class organizes routes into categories (static, dynamic, wildcard) and
	 * creates optimized lookup structures that enable O(1) route matching for
	 * static routes and efficient filtering for dynamic routes.
	 */
	class RouteIndexBuilder {
		
		private RouteSegmentAnalyzer $segmentAnalyzer;
		private array $routeIndex = [];
		
		/**
		 * RouteIndexBuilder constructor
		 * @param RouteSegmentAnalyzer $segmentAnalyzer
		 */
		public function __construct(RouteSegmentAnalyzer $segmentAnalyzer) {
			$this->segmentAnalyzer = $segmentAnalyzer;
		}
		
		/**
		 * This method returns a cached route index if available, or builds a new one
		 * from the provided routes. The index is structured for optimal lookup performance
		 * during request resolution, with routes categorized by type and first segment.
		 * @param array $routes Optional array of routes to build index from
		 * @return array The complete route index with static, dynamic, and wildcard categories
		 */
		public function getRouteIndex(array $routes = []): array {
			// Return cached index if already built and no new routes provided
			if (!empty($this->routeIndex) && empty($routes)) {
				return $this->routeIndex;
			}
			
			// Build fresh index if routes provided or no cached index exists
			if (!empty($routes)) {
				$this->routeIndex = $this->buildRouteIndex($routes);
			}
			
			return $this->routeIndex;
		}
		
		/**
		 * Build route index grouped by type for optimal lookup performance
		 *
		 * This method creates a three-tier indexing system:
		 * 1. Route Type (static, dynamic, wildcard) - for algorithmic optimization
		 * 2. First Segment - for O(1) static route lookups
		 * 3. Route List - actual route definitions for matching
		 *
		 * The indexing strategy dramatically improves performance by:
		 * - Enabling instant static route resolution
		 * - Reducing dynamic route search space
		 * - Deferring wildcard routes to last resort
		 *
		 * @param array $routes Array of compiled route definitions
		 * @return array Structured index with three main categories
		 */
		public function buildRouteIndex(array $routes): array {
			// Initialize index structure with three route categories
			// static: routes with no parameters (e.g., /about, /contact)
			// dynamic: routes with parameters (e.g., /user/{id}, /post/{slug})
			// wildcard: routes that catch all remaining paths (e.g., /api/*)
			$index = [
				'static'   => [],
				'dynamic'  => [],
				'wildcard' => []
			];
			
			foreach ($routes as $route) {
				// Extract the first path segment to use as index key for static routes
				// This enables O(1) lookup for static routes by first segment
				$firstSegment = $this->getFirstSegment($route['route_path']);
				
				// Determine the route type based on path pattern analysis
				$routeType = $this->segmentAnalyzer->classifyRoute($route);
				
				// Group routes for fast lookup based on their classification
				switch ($routeType) {
					case 'static':
						// Static routes are indexed by first segment for instant lookup
						if ($firstSegment) {
							$index['static'][$firstSegment][] = $route;
						} else {
							// Handle edge case of root route ("/")
							$index['static'][''][] = $route;
						}
						break;
					
					case 'wildcard':
						// Wildcard routes go in a separate category as last resort
						$index['wildcard'][] = $route;
						break;
					
					case 'dynamic':
					default:
						// Dynamic routes with variables need sequential matching
						$index['dynamic'][] = $route;
						break;
				}
			}
			
			// Sort dynamic and wildcard routes by priority for proper matching order
			// Higher priority routes should be matched first
			usort($index['dynamic'], fn($a, $b) => $b['priority'] <=> $a['priority']);
			usort($index['wildcard'], fn($a, $b) => $b['priority'] <=> $a['priority']);
			
			// Sort static route groups by priority as well
			foreach ($index['static'] as &$staticGroup) {
				usort($staticGroup, fn($a, $b) => $b['priority'] <=> $a['priority']);
			}
			
			return $index;
		}
		
		/**
		 * This method provides useful metrics about the route distribution
		 * and index structure, which can be helpful for debugging performance
		 * issues or understanding the routing structure of your application.
		 * @return array Associative array with route statistics
		 */
		public function getIndexStatistics(): array {
			// Get the complete route index structure containing static, dynamic, and wildcard routes
			$index = $this->getRouteIndex();
			
			// Count total static routes by summing routes across all static segments
			// Static routes are grouped by path segments for O(1) lookup performance
			$staticCount = array_reduce($index['static'], function($carry, $routes) {
				return $carry + count($routes);
			}, 0);
			
			// Count the number of unique static path segments
			// This indicates how many different static paths exist in the index
			$staticSegments = count($index['static']);
			
			// Count dynamic routes (routes with parameters like /user/{id})
			// These require pattern matching and are slower than static routes
			$dynamicCount = count($index['dynamic']);
			
			// Count wildcard routes (catch-all routes like /admin/*)
			// These are evaluated last and have the lowest performance
			$wildcardCount = count($index['wildcard']);
			
			// Calculate total routes across all categories
			$totalRoutes = $staticCount + $dynamicCount + $wildcardCount;
			
			// Return comprehensive statistics about route index composition
			return [
				// Basic route counts by category
				'total_routes'     => $totalRoutes,
				'static_routes'    => $staticCount,        // Fastest to resolve
				'dynamic_routes'   => $dynamicCount,       // Medium performance
				'wildcard_routes'  => $wildcardCount,      // Slowest to resolve
				
				// Index structure metrics
				'static_segments'  => $staticSegments,     // Number of unique static path prefixes
				
				// Performance indicator: higher percentage means better routing performance
				// Static routes are resolved in O(1) time vs O(n) for dynamic/wildcard
				'efficiency_ratio' => $totalRoutes > 0 ? round(($staticCount / $totalRoutes) * 100, 2) : 0
			];
		}
		
		/**
		 * Clear the cached route index
		 * @return void
		 */
		public function clearIndex(): void {
			$this->routeIndex = [];
		}
		
		/**
		 * Get the first segment of a route path for indexing
		 * @param string $routePath The complete route path
		 * @return string The first segment, or empty string for root routes
		 */
		private function getFirstSegment(string $routePath): string {
			return $this->segmentAnalyzer->getFirstSegment($routePath);
		}
	}