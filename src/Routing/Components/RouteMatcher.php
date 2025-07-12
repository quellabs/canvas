<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	use Quellabs\Canvas\Routing\Strategies\SegmentMatchingStrategyInterface;
	use Quellabs\Canvas\Routing\Strategies\StaticSegmentStrategy;
	use Quellabs\Canvas\Routing\Strategies\VariableSegmentStrategy;
	use Quellabs\Canvas\Routing\Strategies\SingleWildcardStrategy;
	use Quellabs\Canvas\Routing\Strategies\MultiWildcardStrategy;
	use Quellabs\Canvas\Routing\Strategies\PartialVariableStrategy;
	
	/**
	 * RouteMatcher
	 *
	 * Handles the final matching phase of URL routing by comparing incoming requests
	 * against pre-filtered route candidates using compiled route patterns.
	 *
	 * This class takes route candidates that have already passed through pre-filtering
	 * (HTTP method, segment count, static segment filtering) and performs the detailed
	 * pattern matching to determine exact matches and extract route variables.
	 *
	 * Key responsibilities:
	 * - Static vs dynamic route optimization with different matching strategies
	 * - Pattern matching using compiled route segments and matching strategies
	 * - Variable extraction from dynamic URL segments (parameters, wildcards)
	 * - Early elimination through compatibility checks and segment validation
	 * - Support for complex route patterns including partial variables and multi-wildcards
	 *
	 * The matcher uses a strategy pattern to handle different segment types:
	 * - Static segments: exact string matching
	 * - Variable segments: parameter extraction with optional type constraints
	 * - Wildcard segments: single (*) and multi (**) segment consumption
	 * - Partial variables: mixed static/dynamic segments (e.g., "v{path:**}")
	 *
	 * Performance optimizations include early exit conditions, pre-validation of
	 * segment counts, and specialized handling for static routes that bypass
	 * expensive variable extraction.
	 */
	class RouteMatcher {
		
		private array $strategies = [];
		private bool $matchTrailingSlashes;
		
		/**
		 * RouteMatcher constructor
		 * @param bool $matchTrailingSlashes
		 */
		public function __construct(bool $matchTrailingSlashes = false) {
			$this->matchTrailingSlashes = $matchTrailingSlashes;
		}
		
		/**
		 * Match a URL against a single route with optimized pre-checks
		 *
		 * This method performs efficient route matching by applying early exit conditions
		 * and handling both static and dynamic routes with parameter extraction.
		 *
		 * @param array $routeData Complete route configuration including pattern, methods, and metadata
		 * @param array $requestUrl URL segments split by '/' for matching against route pattern
		 * @param string $originalUrl The full original URL string for trailing slash validation
		 * @param string $requestMethod HTTP method (GET, POST, PUT, DELETE, etc.)
		 * @return array|null Returns matched route data with extracted parameters, or null if no match
		 */
		public function matchRoute(array $routeData, array $requestUrl, string $originalUrl, string $requestMethod): ?array {
			// OPTIMIZATION: Early exit if HTTP method doesn't match
			// This prevents unnecessary processing for routes that don't support the request method
			if (!in_array($requestMethod, $routeData['http_methods'])) {
				return null;
			}
			
			// VALIDATION: Check trailing slash consistency if strict matching is enabled
			// Ensures URL format matches exactly what the route expects (with/without trailing slash)
			if ($this->matchTrailingSlashes && !$this->trailingSlashMatches($originalUrl, $routeData['route_path'])) {
				return null;
			}
			
			// Extract the compiled pattern and calculate segment counts for comparison
			$compiledPattern = $routeData['compiled_pattern'];
			$segmentCount = count($requestUrl);      // Number of URL segments to match
			$patternCount = count($compiledPattern); // Number of pattern segments defined
			
			// BRANCH 1: Handle static routes (no dynamic parameters)
			// Static routes are faster to process as they only require exact string comparison
			if ($this->isStaticCompiledRoute($compiledPattern)) {
				// DEBUG: Log when processing static routes with wildcard patterns
				// This helps identify potential performance issues with complex static routes
				if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
					error_log("Taking STATIC route path");
				}
				
				// VALIDATION: Static routes must have exact segment count match
				// If counts don't match, this route cannot possibly match the request
				if ($segmentCount !== $patternCount) {
					return null;
				}
				
				// Delegate to optimized static route matching algorithm
				return $this->matchStaticRoute($compiledPattern, $requestUrl, $routeData);
			}
			
			// BRANCH 2: Handle dynamic routes (contains parameters, wildcards, etc.)
			// Dynamic routes require more complex processing to extract parameter values
			return $this->matchDynamicRoute($compiledPattern, $requestUrl, $routeData, $segmentCount, $patternCount);
		}
		
		/**
		 * ENHANCED: More efficient static route detection
		 * @param array $compiledPattern
		 * @return bool
		 */
		public function isStaticCompiledRoute(array $compiledPattern): bool {
			// Early exit for empty patterns
			if (empty($compiledPattern)) {
				return true;
			}
			
			// Check all segments efficiently
			foreach ($compiledPattern as $segment) {
				if ($segment['type'] !== 'static') {
					return false;
				}
			}
			
			return true;
		}
		
		/**
		 *  Optimized static route matching with early termination
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @return array|null
		 */
		private function matchStaticRoute(array $compiledPattern, array $requestUrl, array $routeData): ?array {
			//  Single loop with early termination
			for ($i = 0; $i < count($compiledPattern); $i++) {
				if ($compiledPattern[$i]['original'] !== $requestUrl[$i]) {
					return null; // Early termination on first mismatch
				}
			}
			
			// All segments matched
			return [
				'http_methods' => $routeData['http_methods'],
				'controller'   => $routeData['controller'],
				'method'       => $routeData['method'],
				'route'        => $routeData['route'],
				'variables'    => [] // Static routes have no variables
			];
		}

		/**
		 * Optimized dynamic route matching with segment count pre-validation
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @param int $segmentCount
		 * @param int $patternCount
		 * @return array|null
		 */
		private function matchDynamicRoute(array $compiledPattern, array $requestUrl, array $routeData, int $segmentCount, int $patternCount): ?array {
			// Early exit: validate segment counts based on route type
			if (!$this->routeHasWildcards($compiledPattern)) {
				// Non-wildcard dynamic routes must have exact segment count
				if ($segmentCount !== $patternCount) {
					return null;
				}
			} else {
				// Wildcard routes need minimum segment validation
				$minRequiredSegments = $this->calculateMinimumRequiredSegments($compiledPattern);
				
				if ($segmentCount < $minRequiredSegments) {
					return null;
				}
			}
			
			// Attempt pattern matching with variables extraction
			$variables = [];
			if (!$this->urlMatchesCompiledRoute($requestUrl, $compiledPattern, $variables)) {
				return null;
			}
			
			// Success: return matched route data
			return [
				'http_methods' => $routeData['http_methods'],
				'controller'   => $routeData['controller'],
				'method'       => $routeData['method'],
				'route'        => $routeData['route'],
				'variables'    => $variables
			];
		}
		
		/**
		 * Check if route has wildcard segments
		 * @param array $compiledPattern
		 * @return bool
		 */
		private function routeHasWildcards(array $compiledPattern): bool {
			foreach ($compiledPattern as $segment) {
				// Check standard wildcard types
				if (in_array($segment['type'], ['single_wildcard', 'multi_wildcard', 'multi_wildcard_var'])) {
					return true;
				}
				
				// Check for partial variables with wildcards (like "v{path:**}")
				if ($segment['type'] === 'partial_variable' && !empty($segment['is_multi_wildcard'])) {
					return true;
				}
				
				// Check for wildcard variables
				if ($segment['type'] === 'variable' && !empty($segment['is_multi_wildcard'])) {
					return true;
				}
			}
			
			return false;
		}
		
		/**
		 * NEW: Calculate minimum required segments for a route pattern
		 * @param array $compiledPattern
		 * @return int
		 */
		private function calculateMinimumRequiredSegments(array $compiledPattern): int {
			$minSegments = 0;
			
			foreach ($compiledPattern as $segment) {
				// Multi-wildcards can consume zero or more segments
				if (in_array($segment['type'], ['multi_wildcard', 'multi_wildcard_var'])) {
					continue;
				}
				
				// Multi-wildcard variables can also consume zero or more
				if ($segment['type'] === 'variable' && !empty($segment['is_multi_wildcard'])) {
					continue;
				}
				
				// All other segment types require at least one URL segment
				$minSegments++;
			}
			
			return $minSegments;
		}
		
		/**
		 * ENHANCED: Optimized pattern matching with improved context handling
		 * @param array $requestUrl
		 * @param array $compiledPattern
		 * @param array &$variables
		 * @return bool
		 */
		private function urlMatchesCompiledRoute(array $requestUrl, array $compiledPattern, array &$variables): bool {
			// ENHANCED: Initialize context with pre-calculated lengths
			$context = new MatchingContext($requestUrl, $compiledPattern);
			
			// ENHANCED: Optimized main matching loop
			while ($context->hasMoreSegments()) {
				$segment = $context->getCurrentRouteSegment();
				$strategy = $this->getStrategy($segment['type']);
				
				$result = $strategy->match($segment, $context);
				
				// ENHANCED: Optimized result handling
				switch ($result) {
					case MatchResult::COMPLETE_MATCH:
						$variables = $context->getVariables();
						return true;
					
					case MatchResult::NO_MATCH:
						return false;
					
					case MatchResult::CONTINUE_MATCHING:
						$context->advance();
						break;
				}
			}
			
			// Extract variables and validate final state
			$variables = $context->getVariables();
			return $context->validateFinalMatch();
		}
		
		/**
		 * ENHANCED: Optimized strategy retrieval with better caching
		 * @param string $segmentType
		 * @return SegmentMatchingStrategyInterface
		 * @throws \InvalidArgumentException
		 */
		private function getStrategy(string $segmentType): SegmentMatchingStrategyInterface {
			// ENHANCED: Use null coalescing for cleaner code
			return $this->strategies[$segmentType] ??= $this->createStrategy($segmentType);
		}
		
		/**
		 * NEW: Factory method for creating strategies
		 * @param string $segmentType
		 * @return SegmentMatchingStrategyInterface
		 * @throws \InvalidArgumentException
		 */
		private function createStrategy(string $segmentType): SegmentMatchingStrategyInterface {
			return match ($segmentType) {
				'static' => new StaticSegmentStrategy(),
				'variable' => new VariableSegmentStrategy(),
				'single_wildcard' => new SingleWildcardStrategy(),
				'multi_wildcard', 'multi_wildcard_var' => new MultiWildcardStrategy(),
				'partial_variable' => new PartialVariableStrategy(),
				default => throw new \InvalidArgumentException("Unknown segment type: {$segmentType}")
			};
		}
		
		/**
		 * ENHANCED: More efficient trailing slash matching
		 * @param string $originalUrl
		 * @param string $routePath
		 * @return bool
		 */
		private function trailingSlashMatches(string $originalUrl, string $routePath): bool {
			// ENHANCED: Early exit for root paths
			if ($originalUrl === '/' || $routePath === '/') {
				return $originalUrl === $routePath;
			}
			
			// ENHANCED: Single comparison with length check
			$urlLength = strlen($originalUrl);
			$routeLength = strlen($routePath);
			
			$urlHasTrailingSlash = $urlLength > 1 && $originalUrl[$urlLength - 1] === '/';
			$routeHasTrailingSlash = $routeLength > 1 && $routePath[$routeLength - 1] === '/';
			
			return $urlHasTrailingSlash === $routeHasTrailingSlash;
		}
		
		/**
		 * NEW: Batch route matching for pre-filtered candidates (used by AnnotationResolver)
		 * @param array $candidates Pre-filtered route candidates
		 * @param array $requestUrl Parsed URL segments
		 * @param string $originalUrl Original URL string
		 * @param string $requestMethod HTTP method
		 * @return array Array of matched routes
		 */
		public function matchCandidates(array $candidates, array $requestUrl, string $originalUrl, string $requestMethod): array {
			$results = [];
			
			// ENHANCED: Early exit if no candidates
			if (empty($candidates)) {
				return $results;
			}
			
			// ENHANCED: Pre-calculate values used in loop
			$segmentCount = count($requestUrl);
			
			foreach ($candidates as $route) {
				// ENHANCED: Skip obviously incompatible routes early
				if (!$this->isRouteCompatible($route, $segmentCount, $requestMethod)) {
					continue;
				}
				
				$match = $this->matchRoute($route, $requestUrl, $originalUrl, $requestMethod);
				if ($match !== null) {
					$results[] = $match;
				}
			}
			
			return $results;
		}
		
		/**
		 * NEW: Quick compatibility check for routes
		 * @param array $route Route configuration
		 * @param int $segmentCount Number of URL segments
		 * @param string $requestMethod HTTP method
		 * @return bool True if route might be compatible
		 */
		private function isRouteCompatible(array $route, int $segmentCount, string $requestMethod): bool {
			// Check HTTP method first (fastest check)
			if (!in_array($requestMethod, $route['http_methods'])) {
				return false;
			}
			
			// For static routes, segment count must match exactly
			if ($this->isStaticCompiledRoute($route['compiled_pattern'])) {
				return count($route['compiled_pattern']) === $segmentCount;
			}
			
			// For dynamic routes, check minimum requirements
			$minRequired = $this->calculateMinimumRequiredSegments($route['compiled_pattern']);
			return $segmentCount >= $minRequired;
		}
	}