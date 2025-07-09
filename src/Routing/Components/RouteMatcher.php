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
	 * This refactored version delegates segment matching to specific strategy classes,
	 * making the code more maintainable, testable, and following the Open/Closed Principle.
	 */
	class RouteMatcher {
		
		private bool $matchTrailingSlashes;
		private array $strategies = [];
		
		/**
		 * RouteMatcher constructor
		 * @param bool $matchTrailingSlashes
		 */
		public function __construct(bool $matchTrailingSlashes = false) {
			$this->matchTrailingSlashes = $matchTrailingSlashes;
		}
		
		/**
		 * Match a URL against a single route with compiled patterns
		 * @param array $routeData
		 * @param array $requestUrl
		 * @param string $originalUrl
		 * @param string $requestMethod
		 * @return array|null
		 */
		public function matchRoute(array $routeData, array $requestUrl, string $originalUrl, string $requestMethod): ?array {
			// Early exit if HTTP method doesn't match
			if (!in_array($requestMethod, $routeData['http_methods'])) {
				return null;
			}
			
			// Validate trailing slash requirements
			if ($this->matchTrailingSlashes && !$this->trailingSlashMatches($originalUrl, $routeData['route_path'])) {
				return null;
			}
			
			// Handle static routes with exact segment count matching
			$compiledPattern = $routeData['compiled_pattern'];
			$segmentCount = count($requestUrl);
			$patternCount = count($compiledPattern);
			
			// Static routes must have exact segment count match
			if ($this->isStaticCompiledRoute($compiledPattern)) {
				if ($segmentCount === $patternCount) {
					return $this->matchStaticRoute($compiledPattern, $requestUrl, $routeData);
				}
				
				return null;
			}
			
			// Process dynamic routes with parameters/wildcards
			return $this->matchDynamicRoute($compiledPattern, $requestUrl, $routeData);
		}
		
		/**
		 * Check if compiled route is completely static
		 * @param array $compiledPattern
		 * @return bool
		 */
		public function isStaticCompiledRoute(array $compiledPattern): bool {
			// Iterate through each segment in the compiled pattern
			foreach ($compiledPattern as $segment) {
				// If any segment is not static (could be dynamic, optional, etc.),
				// then the entire route is not static
				if ($segment['type'] !== 'static') {
					return false;
				}
			}
			
			// If we've checked all segments and they're all static,
			// then the entire route is static
			return true;
		}
		
		/**
		 * Match static route using pre-compiled patterns
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @return array|null
		 */
		private function matchStaticRoute(array $compiledPattern, array $requestUrl, array $routeData): ?array {
			// Loop through each segment of the compiled pattern
			for ($i = 0; $i < count($compiledPattern); $i++) {
				// Compare the original pattern segment with the corresponding request URL segment
				// If any segment doesn't match exactly, this route is not a match
				if ($compiledPattern[$i]['original'] !== $requestUrl[$i]) {
					return null;
				}
			}
			
			// If all segments match, return the route data with empty variables array
			// (static routes don't have dynamic variables)
			return [
				'http_methods' => $routeData['http_methods'], // Allowed HTTP methods for this route
				'controller'   => $routeData['controller'],   // Controller class to handle the request
				'method'       => $routeData['method'],       // Method within the controller to call
				'route'        => $routeData['route'],        // Original route pattern
				'variables'    => []                          // Empty since static routes have no variables
			];
		}
		
		/**
		 * Match dynamic route using pre-compiled patterns and strategies
		 * @param array $compiledPattern
		 * @param array $requestUrl
		 * @param array $routeData
		 * @return array|null
		 */
		private function matchDynamicRoute(array $compiledPattern, array $requestUrl, array $routeData): ?array {
			$variables = [];
			
			if ($this->urlMatchesCompiledRoute($requestUrl, $compiledPattern, $variables)) {
				return [
					'http_methods' => $routeData['http_methods'],
					'controller'   => $routeData['controller'],
					'method'       => $routeData['method'],
					'route'        => $routeData['route'],
					'variables'    => $variables
				];
			}
			
			return null;
		}
		
		/**
		 * Determines if a request URL matches a compiled route pattern by comparing segments.
		 * Uses the strategy pattern to handle different segment types (literal, parameter, wildcard, etc.)
		 * and extracts route variables when a match is found.
		 * @param array $requestUrl The URL segments from the incoming request
		 * @param array $compiledPattern The compiled route pattern segments to match against
		 * @param array &$variables Reference to array that will be populated with extracted route variables
		 * @return bool True if URL matches the route pattern, false otherwise
		 */
		private function urlMatchesCompiledRoute(array $requestUrl, array $compiledPattern, array &$variables): bool {
			// Initialize matching context with request URL and compiled route pattern
			// This context object tracks the current position in both arrays and maintains state
			$context = new MatchingContext($requestUrl, $compiledPattern);
			
			// Process each segment of the route pattern sequentially
			while ($context->hasMoreSegments()) {
				// Get the current route segment definition (contains type and constraints)
				$segment = $context->getCurrentRouteSegment();
				
				// Select appropriate matching strategy based on segment type
				// (e.g., literal, parameter, wildcard, optional, etc.)
				$strategy = $this->getStrategy($segment['type']);
				
				// Execute the matching logic for this segment type
				// Strategy handles the specific matching rules and updates context
				$result = $strategy->match($segment, $context);
				
				// Handle different result types returned by the strategy
				if ($result === MatchResult::COMPLETE_MATCH) {
					// Early termination - route fully matched (e.g., wildcard consumed remaining URL)
					$variables = $context->getVariables();
					return true;
				}
				
				if ($result === MatchResult::NO_MATCH) {
					// The segment failed to match - entire route fails
					return false;
				}
				
				// CONTINUE_MATCHING - this segment matched, proceed to next segment
				// Advance both URL and pattern pointers to next positions
				$context->advance();
			}
			
			// All segments processed - extract any captured variables from context
			$variables = $context->getVariables();
			
			// Perform final validation (e.g., check if all URL segments were consumed,
			// validate required parameters are present, etc.)
			return $context->validateFinalMatch();
		}
		
		/**
		 * Retrieves the appropriate matching strategy for a given segment type.
		 * Uses lazy instantiation to create strategy instances only when first needed.
		 * Each segment type (literal, parameter, wildcard, optional, etc.) has its own
		 * specialized strategy that knows how to match that type of URL segment.
		 * @param string $segmentType The type of route segment (e.g., 'literal', 'parameter', 'wildcard')
		 * @return SegmentMatchingStrategyInterface The strategy instance for handling this segment type
		 * @throws \InvalidArgumentException When the segment type is not registered or supported
		 */
		private function getStrategy(string $segmentType): SegmentMatchingStrategyInterface {
			// Check if we already have an instance for this segment type
			if (isset($this->strategies[$segmentType])) {
				return $this->strategies[$segmentType];
			}
			
			// Lazy instantiate the strategy on first use
			$strategy = match ($segmentType) {
				'static' => new StaticSegmentStrategy(),
				'variable' => new VariableSegmentStrategy(),
				'single_wildcard' => new SingleWildcardStrategy(),
				'multi_wildcard', 'multi_wildcard_var' => new MultiWildcardStrategy(),
				'partial_variable' => new PartialVariableStrategy(),
				default => throw new \InvalidArgumentException("Unknown segment type: {$segmentType}")
			};
			
			// Cache the instance for future use
			return $this->strategies[$segmentType] = $strategy;
		}
		
		/**
		 * Check if trailing slash requirements match
		 * @param string $originalUrl
		 * @param string $routePath
		 * @return bool
		 */
		private function trailingSlashMatches(string $originalUrl, string $routePath): bool {
			$urlHasTrailingSlash = strlen($originalUrl) > 1 && str_ends_with($originalUrl, '/');
			$routeHasTrailingSlash = strlen($routePath) > 1 && str_ends_with($routePath, '/');
			return $urlHasTrailingSlash === $routeHasTrailingSlash;
		}
	}