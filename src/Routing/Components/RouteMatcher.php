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
		 * ENHANCED: Match a URL against a single route with optimized pre-checks
		 * @param array $routeData
		 * @param array $requestUrl
		 * @param string $originalUrl
		 * @param string $requestMethod
		 * @return array|null
		 */
		public function matchRoute(array $routeData, array $requestUrl, string $originalUrl, string $requestMethod): ?array {
			if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
				error_log("=== RouteMatcher::matchRoute DEBUG ===");
				error_log("Route path: " . ($routeData['route_path'] ?? 'unknown'));
				error_log("Request URL segments: " . print_r($requestUrl, true));
				error_log("HTTP methods match: " . (in_array($requestMethod, $routeData['http_methods']) ? 'YES' : 'NO'));
			}
			
			// Early exit if HTTP method doesn't match
			if (!in_array($requestMethod, $routeData['http_methods'])) {
				return null;
			}
			
			// Trailing slash validation
			if ($this->matchTrailingSlashes && !$this->trailingSlashMatches($originalUrl, $routeData['route_path'])) {
				if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
					error_log("TRAILING SLASH MISMATCH");
				}
				return null;
			}
			
			$compiledPattern = $routeData['compiled_pattern'];
			$segmentCount = count($requestUrl);
			$patternCount = count($compiledPattern);
			
			if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
				error_log("Segment count: $segmentCount, Pattern count: $patternCount");
				error_log("Is static route: " . ($this->isStaticCompiledRoute($compiledPattern) ? 'YES' : 'NO'));
			}
			
			// Static route handling
			if ($this->isStaticCompiledRoute($compiledPattern)) {
				if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
					error_log("Taking STATIC route path");
				}
				if ($segmentCount !== $patternCount) {
					return null;
				}
				return $this->matchStaticRoute($compiledPattern, $requestUrl, $routeData);
			}
			
			if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
				error_log("Taking DYNAMIC route path");
			}
			
			// Dynamic route handling
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
		 * ENHANCED: Optimized static route matching with early termination
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @return array|null
		 */
		private function matchStaticRoute(array $compiledPattern, array $requestUrl, array $routeData): ?array {
			// ENHANCED: Single loop with early termination
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
		 * ENHANCED: Optimized dynamic route matching with segment count pre-validation
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @param int $segmentCount
		 * @param int $patternCount
		 * @return array|null
		 */
		private function matchDynamicRoute(array $compiledPattern, array $requestUrl, array $routeData, int $segmentCount, int $patternCount): ?array {
			if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
				error_log("=== matchDynamicRoute DEBUG ===");
				error_log("Segment count: $segmentCount, Pattern count: $patternCount");
				error_log("Route has wildcards: " . ($this->routeHasWildcards($compiledPattern) ? 'YES' : 'NO'));
			}
			
			// Pre-validate segment counts for non-wildcard routes
			if (!$this->routeHasWildcards($compiledPattern)) {
				if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
					error_log("Non-wildcard route - checking exact segment count");
				}
				// Non-wildcard dynamic routes must have exact segment count
				if ($segmentCount !== $patternCount) {
					if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
						error_log("SEGMENT COUNT MISMATCH for non-wildcard route");
					}
					return null;
				}
			} else {
				if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
					error_log("Wildcard route - checking minimum segments");
				}
				// Wildcard routes need minimum segment validation
				$minRequiredSegments = $this->calculateMinimumRequiredSegments($compiledPattern);
				if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
					error_log("Min required segments: $minRequiredSegments");
				}
				if ($segmentCount < $minRequiredSegments) {
					if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
						error_log("INSUFFICIENT SEGMENTS for wildcard route");
					}
					return null;
				}
			}
			
			if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
				error_log("Proceeding to urlMatchesCompiledRoute");
			}
			
			// Proceed with detailed pattern matching
			$variables = [];
			if ($this->urlMatchesCompiledRoute($requestUrl, $compiledPattern, $variables)) {
				if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
					error_log("urlMatchesCompiledRoute SUCCESS");
					error_log("Variables: " . print_r($variables, true));
				}
				return [
					'http_methods' => $routeData['http_methods'],
					'controller'   => $routeData['controller'],
					'method'       => $routeData['method'],
					'route'        => $routeData['route'],
					'variables'    => $variables
				];
			}
			
			if (str_contains($routeData['route_path'] ?? '', 'path:**')) {
				error_log("urlMatchesCompiledRoute FAILED");
			}
			
			return null;
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