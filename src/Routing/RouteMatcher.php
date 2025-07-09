<?php
	
	namespace Quellabs\Canvas\Routing;
	
	/**
	 * Handles URL matching against compiled routes using optimized algorithms.
	 * This class contains the core matching logic that determines if an incoming
	 * URL matches a specific route pattern and extracts variable values from
	 * dynamic route segments.
	 */
	class RouteMatcher {
		
		private bool $matchTrailingSlashes;
		
		/**
		 * RouteMatcher constructor
		 * @param bool $matchTrailingSlashes
		 */
		public function __construct(bool $matchTrailingSlashes = false) {
			$this->matchTrailingSlashes = $matchTrailingSlashes;
		}
		
		/**
		 * Match a URL against a single route with compiled patterns
		 *
		 * This method performs optimized route matching using pre-compiled patterns.
		 * It handles different route types (static, dynamic, wildcard) with specific
		 * algorithms optimized for each type.
		 *
		 * @param array $routeData Complete route data with compiled patterns
		 * @param array $requestUrl Parsed URL segments from the request
		 * @param string $originalUrl Original URL string for trailing slash validation
		 * @param string $requestMethod HTTP method (GET, POST, etc.)
		 * @return array|null Route match data or null if no match
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
				return $segmentCount === $patternCount ? $this->matchStaticRoute($compiledPattern, $requestUrl, $routeData) : null;
			}
			
			// Process dynamic routes with parameters/wildcards
			return $this->matchDynamicRoute($compiledPattern, $requestUrl, $routeData);
		}
		
		/**
		 * Check if compiled route is completely static
		 * @param array $compiledPattern Array of compiled route segments
		 * @return bool True if all segments are static
		 */
		public function isStaticCompiledRoute(array $compiledPattern): bool {
			foreach ($compiledPattern as $segment) {
				if ($segment['type'] !== 'static') {
					return false;
				}
			}
			
			return true;
		}
		
		/**
		 * Match static route using pre-compiled patterns
		 * @param array $compiledPattern Pre-compiled route pattern
		 * @param array $requestUrl URL segments to match
		 * @param array $routeData Original route data
		 * @return array|null Match result or null if no match
		 */
		private function matchStaticRoute(array $compiledPattern, array $requestUrl, array $routeData): ?array {
			// Loop through each segment of the compiled pattern
			for ($i = 0; $i < count($compiledPattern); $i++) {
				// Compare the original pattern segment with the corresponding request URL segment
				if ($compiledPattern[$i]['original'] !== $requestUrl[$i]) {
					return null; // No match found
				}
			}
			
			// All segments matched successfully, return the route data
			return [
				'http_methods' => $routeData['http_methods'],
				'controller'   => $routeData['controller'],
				'method'       => $routeData['method'],
				'route'        => $routeData['route'],
				'variables'    => [] // Static routes have no variables
			];
		}
		
		/**
		 * Match dynamic route using pre-compiled patterns
		 * @param array $compiledPattern Pre-compiled route pattern
		 * @param array $requestUrl URL segments to match
		 * @param array $routeData Original route data
		 * @return array|null Match result with extracted variables or null if no match
		 */
		private function matchDynamicRoute(array $compiledPattern, array $requestUrl, array $routeData): ?array {
			$variables = [];
			
			// Use the URL matching logic with compiled patterns
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
		 * Core URL matching algorithm using compiled patterns
		 * @param array $requestUrl URL segments to match
		 * @param array $compiledPattern Pre-compiled route pattern
		 * @param array &$variables Reference to variables array for extraction
		 * @return bool True if URL matches the pattern
		 */
		private function urlMatchesCompiledRoute(array $requestUrl, array $compiledPattern, array &$variables): bool {
			$routeIndex = 0;
			$urlIndex = 0;
			
			while ($this->hasMoreSegments($compiledPattern, $routeIndex, $requestUrl, $urlIndex)) {
				$segment = $compiledPattern[$routeIndex];
				
				// Handle different segment types using pre-compiled data
				switch ($segment['type']) {
					case 'multi_wildcard':
					case 'multi_wildcard_var':
						$result = $this->handleMultiWildcard(
							$segment,
							$requestUrl,
							$urlIndex,
							$variables,
							$compiledPattern,
							$routeIndex
						);
						
						if ($result === true) {
							return true;
						}
						
						// Calculate consumed segments
						$remainingRouteSegments = count($compiledPattern) - ($routeIndex + 1);
						$remainingUrlSegments = count($requestUrl) - $urlIndex;
						$segmentsConsumed = $remainingUrlSegments - $remainingRouteSegments;
						
						$urlIndex += max(0, $segmentsConsumed);
						$routeIndex++;
						continue 2;
					
					case 'single_wildcard':
						$this->handleSingleWildcard($segment, $requestUrl[$urlIndex], $variables);
						++$urlIndex;
						++$routeIndex;
						continue 2;
					
					case 'partial_variable':
						if ($this->matchPartialVariableSegment($segment, $requestUrl[$urlIndex], $variables)) {
							++$urlIndex;
							++$routeIndex;
							continue 2;
						} else {
							return false;
						}
					
					case 'variable':
						$result = $this->handleVariable($segment, $requestUrl, $urlIndex, $variables);
						
						if ($result === true) {
							return true;
						}
						
						if ($result === false) {
							return false;
						}
						
						++$urlIndex;
						++$routeIndex;
						continue 2;
					
					case 'static':
					default:
						if ($segment['original'] !== $requestUrl[$urlIndex]) {
							return false;
						}
						
						++$routeIndex;
						++$urlIndex;
						continue 2;
				}
			}
			
			return $this->validateFinalMatch($compiledPattern, $routeIndex, $requestUrl, $urlIndex);
		}
		
		/**
		 * Handle multi-wildcard segments with compiled patterns
		 * @param array $segment Current route segment data
		 * @param array $requestUrl Complete URL segments array
		 * @param int $urlIndex Current position in URL
		 * @param array &$variables Variables array for storage
		 * @param array $compiledPattern Complete route pattern
		 * @param int $routeIndex Current position in route pattern
		 * @return bool Always returns false to continue processing
		 */
		private function handleMultiWildcard(array $segment, array $requestUrl, int $urlIndex, array &$variables, array $compiledPattern, int $routeIndex): bool {
			// Calculate how many route segments remain after the current wildcard
			$remainingRouteSegments = count($compiledPattern) - ($routeIndex + 1);
			
			// Calculate how many URL segments remain to be processed
			$remainingUrlSegments = count($requestUrl) - $urlIndex;
			
			// If there are more route segments after this wildcard
			if ($remainingRouteSegments > 0) {
				// Check if we have enough URL segments to satisfy the remaining route
				if ($remainingUrlSegments < $remainingRouteSegments) {
					return false;
				}
				
				// Calculate how many segments this wildcard should consume
				$segmentsToConsume = $remainingUrlSegments - $remainingRouteSegments;
				
				if ($segmentsToConsume < 0) {
					return false;
				}
				
				// Extract the segments that this wildcard will consume
				$consumedSegments = array_slice($requestUrl, $urlIndex, $segmentsToConsume);
			} else {
				// No more route segments after this wildcard, consume all remaining
				$consumedSegments = array_slice($requestUrl, $urlIndex);
			}
			
			// Join the consumed segments back into a path string
			$capturedPath = implode('/', $consumedSegments);
			
			// Store the captured path in the variables array
			if ($segment['variable_name'] === '**') {
				// Anonymous multi-wildcard - store as array
				if (!isset($variables['**'])) {
					$variables['**'] = [];
				}
				$variables['**'][] = $capturedPath;
			} else {
				// Named multi-wildcard - store directly
				$variables[$segment['variable_name']] = $capturedPath;
			}
			
			return false;
		}
		
		/**
		 * Handle single wildcard segments with compiled patterns
		 * @param array $segment Current route segment data
		 * @param string $urlSegment Single URL segment to capture
		 * @param array &$variables Variables array for storage
		 * @return void
		 */
		private function handleSingleWildcard(array $segment, string $urlSegment, array &$variables): void {
			if ($segment['variable_name'] === '*') {
				// Anonymous single wildcard - store as array
				if (!isset($variables['*'])) {
					$variables['*'] = [];
				}
				$variables['*'][] = $urlSegment;
			} else {
				// Named single wildcard - store directly
				$variables[$segment['variable_name']] = $urlSegment;
			}
		}
		
		/**
		 * Handle variable segments with compiled patterns
		 * @param array $segment Current route segment data
		 * @param array $requestUrl Complete URL segments array
		 * @param int $urlIndex Current position in URL
		 * @param array &$variables Variables array for storage
		 * @return bool|null True for multi-wildcard completion, false for validation failure, null for normal variable
		 */
		private function handleVariable(array $segment, array $requestUrl, int $urlIndex, array &$variables): bool|null {
			$variableName = $segment['variable_name'];
			$pattern = $segment['pattern'];
			
			// Handle multi-wildcard variables
			if ($segment['is_multi_wildcard']) {
				// Multi-wildcard consumes all remaining URL segments
				$remainingSegments = array_slice($requestUrl, $urlIndex);
				$variables[$variableName] = implode('/', $remainingSegments);
				return true;
			}
			
			// Handle regular single-segment variables
			$urlSegment = $requestUrl[$urlIndex];
			
			// Validate against pattern if specified
			if ($pattern && !preg_match('/^' . $pattern . '$/', $urlSegment)) {
				return false;
			}
			
			// Store the captured segment
			$variables[$variableName] = $urlSegment;
			return null;
		}
		
		/**
		 * Handle partial variable segments with compiled patterns
		 * @param array $segment Current route segment data
		 * @param string $urlSegment URL segment to match
		 * @param array &$variables Variables array for storage
		 * @return bool True if segment matches and variables were extracted
		 */
		private function matchPartialVariableSegment(array $segment, string $urlSegment, array &$variables): bool {
			$pattern = $segment['compiled_regex'];
			$variableNames = $segment['variable_names'];
			
			// Attempt to match using the pre-compiled regex
			if (preg_match($pattern, $urlSegment, $matches)) {
				// Extract all captured variables
				foreach ($variableNames as $name) {
					if (isset($matches[$name])) {
						$variables[$name] = $matches[$name];
					}
				}
				
				return true;
			}
			
			return false;
		}
		
		/**
		 * Check if there are more segments to process
		 * @param array $routePattern Complete route pattern
		 * @param int $routeIndex Current position in route
		 * @param array $requestUrl Complete URL segments
		 * @param int $urlIndex Current position in URL
		 * @return bool True if both have more segments to process
		 */
		private function hasMoreSegments(array $routePattern, int $routeIndex, array $requestUrl, int $urlIndex): bool {
			return $routeIndex < count($routePattern) && $urlIndex < count($requestUrl);
		}
		
		/**
		 * Validate that route matching is complete and successful
		 * @param array $routePattern Complete route pattern
		 * @param int $routeIndex Final position in route
		 * @param array $requestUrl Complete URL segments
		 * @param int $urlIndex Final position in URL
		 * @return bool True if match is valid and complete
		 */
		private function validateFinalMatch(array $routePattern, int $routeIndex, array $requestUrl, int $urlIndex): bool {
			// All route segments should be processed
			if ($routeIndex < count($routePattern)) {
				return false;
			}
			
			// All URL segments should be processed, unless the last route segment is a multi-wildcard
			if ($urlIndex < count($requestUrl)) {
				$lastRouteSegment = end($routePattern);
				return $this->isMultiWildcardSegment($lastRouteSegment);
			}
			
			return true;
		}
		
		/**
		 * Check if segment is a multi-wildcard type
		 * @param array $segment Route segment data
		 * @return bool True if segment is a multi-wildcard
		 */
		private function isMultiWildcardSegment(array $segment): bool {
			return in_array($segment['type'], ['multi_wildcard', 'multi_wildcard_var']) ||
				($segment['type'] === 'variable' && $segment['is_multi_wildcard']);
		}
		
		/**
		 * Check if trailing slash requirements match
		 * @param string $originalUrl Original request URL
		 * @param string $routePath Route path pattern
		 * @return bool True if trailing slash requirements are compatible
		 */
		private function trailingSlashMatches(string $originalUrl, string $routePath): bool {
			$urlHasTrailingSlash = strlen($originalUrl) > 1 && str_ends_with($originalUrl, '/');
			$routeHasTrailingSlash = strlen($routePath) > 1 && str_ends_with($routePath, '/');
			
			return $urlHasTrailingSlash === $routeHasTrailingSlash;
		}
	}