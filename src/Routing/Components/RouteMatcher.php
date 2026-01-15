<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	use Quellabs\Canvas\Routing\SegmentTypes;
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
		 * Pre-initializes all strategy instances for reuse
		 * @param bool $matchTrailingSlashes
		 */
		public function __construct(bool $matchTrailingSlashes = false) {
			$this->matchTrailingSlashes = $matchTrailingSlashes;
			
			// Pre-create all strategies once for performance
			$this->strategies = [
				SegmentTypes::STATIC             => new StaticSegmentStrategy(),
				SegmentTypes::VARIABLE           => new VariableSegmentStrategy(),
				SegmentTypes::SINGLE_WILDCARD    => new SingleWildcardStrategy(),
				SegmentTypes::MULTI_WILDCARD     => new MultiWildcardStrategy(),
				SegmentTypes::MULTI_WILDCARD_VAR => new MultiWildcardStrategy(),
				SegmentTypes::PARTIAL_VARIABLE   => new PartialVariableStrategy(),
			];
		}
		
		/**
		 * Match a URL against a single route with optimized pre-checks
		 * @param array $routeData Complete route configuration
		 * @param array $requestUrl URL segments
		 * @param string $originalUrl Full original URL
		 * @param string $requestMethod HTTP method
		 * @return array|null Matched route data or null
		 */
		public function matchRoute(array $routeData, array $requestUrl, string $originalUrl, string $requestMethod): ?array {
			// Early exit: HTTP method check
			if (!in_array($requestMethod, $routeData['http_methods'], true)) {
				return null;
			}
			
			// Early exit: trailing slash validation
			if ($this->matchTrailingSlashes && !$this->trailingSlashMatches($originalUrl, $routeData['route_path'])) {
				return null;
			}
			
			$compiledPattern = $routeData['compiled_pattern'];
			$segmentCount = count($requestUrl);
			$patternCount = count($compiledPattern);
			
			// Branch on route type for optimal handling
			if ($this->isStaticRoute($compiledPattern)) {
				return $this->matchStaticRoute(
					$compiledPattern,
					$requestUrl,
					$routeData,
					$segmentCount,
					$patternCount
				);
			}
			
			return $this->matchDynamicRoute($compiledPattern, $requestUrl, $routeData, $segmentCount, $patternCount);
		}
		
		/**
		 * Check if route is fully static (optimized)
		 * @param array $compiledPattern
		 * @return bool
		 */
		private function isStaticRoute(array $compiledPattern): bool {
			if (empty($compiledPattern)) {
				return true;
			}
			
			// Check if all segments are static type
			foreach ($compiledPattern as $segment) {
				if (!SegmentTypes::isStatic($segment)) {
					return false;
				}
			}
			
			return true;
		}
		
		/**
		 * Match static route (exact string comparison only)
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @param int $segmentCount
		 * @param int $patternCount
		 * @return array|null
		 */
		private function matchStaticRoute(array $compiledPattern, array $requestUrl, array $routeData, int $segmentCount, int $patternCount): ?array {
			// Static routes require exact segment count match
			if ($segmentCount !== $patternCount) {
				return null;
			}
			
			// Compare all segments with early termination
			for ($i = 0; $i < $patternCount; $i++) {
				if ($compiledPattern[$i]['original'] !== $requestUrl[$i]) {
					return null;
				}
			}
			
			// All segments matched
			return [
				'http_methods' => $routeData['http_methods'],
				'controller'   => $routeData['controller'],
				'method'       => $routeData['method'],
				'route'        => $routeData['route'],
				'variables'    => []
			];
		}
		
		/**
		 * Match dynamic route (contains variables/wildcards)
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @param int $segmentCount
		 * @param int $patternCount
		 * @return array|null
		 */
		private function matchDynamicRoute(array $compiledPattern, array $requestUrl, array $routeData, int $segmentCount, int $patternCount): ?array {
			// Validate segment counts based on route capabilities
			if (!$this->hasWildcards($compiledPattern)) {
				// Non-wildcard routes need exact count
				if ($segmentCount !== $patternCount) {
					return null;
				}
			} else {
				// Wildcard routes need minimum count
				$minRequired = $this->calculateMinimumSegments($compiledPattern);
				if ($segmentCount < $minRequired) {
					return null;
				}
			}
			
			// Attempt pattern matching
			$variables = [];
			if (!$this->matchPattern($requestUrl, $compiledPattern, $variables)) {
				return null;
			}
			
			return [
				'http_methods' => $routeData['http_methods'],
				'controller'   => $routeData['controller'],
				'method'       => $routeData['method'],
				'route'        => $routeData['route'],
				'variables'    => $variables
			];
		}
		
		/**
		 * Check if route contains any wildcard segments
		 * Uses centralized SegmentTypes for consistency
		 * @param array $compiledPattern
		 * @return bool
		 */
		private function hasWildcards(array $compiledPattern): bool {
			foreach ($compiledPattern as $segment) {
				if (SegmentTypes::isWildcard($segment) || SegmentTypes::isMultiWildcard($segment)) {
					return true;
				}
			}
			return false;
		}
		
		/**
		 * Calculate minimum required URL segments for a route
		 * @param array $compiledPattern
		 * @return int
		 */
		private function calculateMinimumSegments(array $compiledPattern): int {
			$minSegments = 0;
			
			foreach ($compiledPattern as $segment) {
				// Multi-wildcards can consume zero segments
				if (SegmentTypes::isMultiWildcard($segment)) {
					continue;
				}
				
				// All other types require at least one segment
				$minSegments++;
			}
			
			return $minSegments;
		}
		
		/**
		 * Execute pattern matching using strategy pattern
		 * @param array $requestUrl
		 * @param array $compiledPattern
		 * @param array &$variables
		 * @return bool
		 */
		private function matchPattern(array $requestUrl, array $compiledPattern, array &$variables): bool {
			$context = new MatchingContext($requestUrl, $compiledPattern);
			
			while ($context->hasMoreSegments()) {
				$segment = $context->getCurrentRouteSegment();
				$strategy = $this->getStrategy($segment['type']);
				
				$result = $strategy->match($segment, $context);
				
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
			
			$variables = $context->getVariables();
			return $context->validateFinalMatch();
		}
		
		/**
		 * Get cached strategy instance for segment type
		 * @param string $segmentType
		 * @return SegmentMatchingStrategyInterface
		 * @throws \InvalidArgumentException
		 */
		private function getStrategy(string $segmentType): SegmentMatchingStrategyInterface {
			if (!isset($this->strategies[$segmentType])) {
				throw new \InvalidArgumentException("Unknown segment type: {$segmentType}");
			}
			
			return $this->strategies[$segmentType];
		}
		
		/**
		 * Validate trailing slash consistency
		 * @param string $originalUrl
		 * @param string $routePath
		 * @return bool
		 */
		private function trailingSlashMatches(string $originalUrl, string $routePath): bool {
			// Root paths must match exactly
			if ($originalUrl === '/' || $routePath === '/') {
				return $originalUrl === $routePath;
			}
			
			// Compare trailing slash presence
			$urlHasTrailing = str_ends_with($originalUrl, '/');
			$routeHasTrailing = str_ends_with($routePath, '/');
			
			return $urlHasTrailing === $routeHasTrailing;
		}
	}