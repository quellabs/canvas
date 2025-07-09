<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	/**
	 * RouteSegmentAnalyzer
	 *
	 * Handles URL classification and segment analysis for route matching.
	 * This class is responsible for determining segment types, calculating
	 * route priorities, and extracting variable information from route patterns.
	 */
	class RouteSegmentAnalyzer {
		
		/**
		 * Determine the type of route segment
		 *
		 * This method analyzes a single route segment to classify it into one of several
		 * types based on its pattern. The classification determines how the segment will
		 * be processed during route matching and affects the route's priority score.
		 * The order of checks is important - more specific patterns are checked first.
		 *
		 * Segment types (in order of specificity):
		 * - multi_wildcard: ** (matches multiple segments)
		 * - single_wildcard: * (matches one segment)
		 * - multi_wildcard_var: {path:**} or {files:.*} (named multi-wildcard)
		 * - partial_variable: user-{id}-profile (mixed static/variable)
		 * - variable: {id}, {slug} (single variable segment)
		 * - static: user, profile (exact match required)
		 *
		 * @param string $segment The route segment to analyze
		 * @return string The segment type identifier
		 */
		public function getSegmentType(string $segment): string {
			// Define segment type patterns in order of precedence
			// Each type has a checker function that returns true if the segment matches
			$segmentTypes = [
				// Anonymous multi-wildcard: matches unlimited segments
				'multi_wildcard'     => fn($s) => $s === '**',
				
				// Anonymous single wildcard: matches exactly one segment
				'single_wildcard'    => fn($s) => $s === '*',
				
				// Named multi-wildcard variables: {path:**} or {files:.*}
				// These capture multiple segments into a named variable
				'multi_wildcard_var' => fn($s) => str_ends_with($s, ':**}') || str_ends_with($s, ':.*}'),
				
				// Partial variables: segments mixing static text with variables
				// e.g., "user-{id}-profile" or "file.{name}.{ext}"
				'partial_variable'   => fn($s) => $this->hasPartialVariable($s) && !$this->isVariable($s),
				
				// Regular variables: {id}, {slug}, {category:int}
				// Identified by starting with opening brace
				'variable'           => fn($s) => !empty($s) && $s[0] === '{',
				
				// Static segments: exact string matches (fallback case)
				'static'             => fn($s) => true // Always matches as fallback
			];
			
			// Check each type in order until a match is found
			// Order matters: more specific types must be checked before general ones
			foreach ($segmentTypes as $type => $checker) {
				if ($checker($segment)) {
					return $type;
				}
			}
			
			// Fallback to static (should never reach here due to static checker)
			return 'static';
		}
		
		/**
		 * Calculate priority for route (higher = more priority)
		 * More specific routes get higher priority than generic/wildcard routes
		 *
		 * This method implements a sophisticated priority scoring system that ensures
		 * more specific routes are matched before generic ones. The algorithm considers
		 * static segments (exact matches), variable segments, wildcards, and route length
		 * to determine specificity. Higher scores indicate higher priority in route matching.
		 *
		 * Priority factors:
		 * - Static segments increase priority (more specific)
		 * - Variable segments decrease priority (less specific)
		 * - Wildcards heavily decrease priority (least specific)
		 * - Longer routes get slight priority boost
		 * - Fully static routes get significant bonus
		 *
		 * @param string $routePath The complete route path to analyze
		 * @return int Priority score (higher = more specific, matched first)
		 */
		public function calculateRoutePriority(string $routePath): int {
			// Start with a base priority score
			$priority = 1000;
			
			// Parse route into segments, filtering out empty segments
			// e.g., "/user/profile/" becomes ["user", "profile"]
			$segments = $this->parseRoutePath($routePath);
			
			// Count total segments and track static segments for bonuses
			$segmentCount = count($segments);
			$staticSegments = 0;
			$penalties = 0; // Accumulate penalty points for non-specific segments
			
			// Analyze each segment to determine its impact on priority
			foreach ($segments as $segment) {
				// Handle partial variable segments (e.g., "user-{id}-profile")
				if ($this->hasPartialVariable($segment)) {
					// Partial variables are moderately penalized as they're semi-specific
					$penalties += 30;
				} else {
					// Determine the segment type (static, variable, wildcard, etc.)
					$segmentType = $this->getSegmentType($segment);
					
					// Apply type-specific penalty based on how generic the segment is
					$penalties += $this->getSegmentPenalty($segmentType);
					
					// Count static segments for bonus calculation
					if ($segmentType === 'static') {
						$staticSegments++;
					}
				}
			}
			
			// Apply calculated penalties to reduce priority for generic segments
			$priority -= $penalties;
			
			// Bonus points for static segments (20 points each)
			// Static segments make routes more specific and should be prioritized
			$priority += $staticSegments * 20;
			
			// Small bonus for longer routes (5 points per segment)
			// Longer routes are generally more specific than shorter ones
			$priority += $segmentCount * 5;
			
			// Special bonus for completely static routes (no variables/wildcards)
			// These are the most specific possible and should always match first
			if ($penalties === 0) {
				$priority += 100;
			}
			
			return $priority;
		}
		
		/**
		 * Classify route type for indexing optimization
		 * @param array $route Route configuration array with compiled_pattern
		 * @return string 'wildcard', 'dynamic', or 'static'
		 */
		public function classifyRoute(array $route): string {
			// Check each segment for classification
			foreach ($route['compiled_pattern'] as $segment) {
				// Wildcards take precedence (*, **, *var)
				if (in_array($segment['type'], ['multi_wildcard', 'single_wildcard', 'multi_wildcard_var'])) {
					return 'wildcard';
				}
				
				// Variables make route dynamic ({id}, {slug})
				if (in_array($segment['type'], ['variable', 'partial_variable'])) {
					return 'dynamic';
				}
			}
			
			// No variables or wildcards = static route
			return 'static';
		}
		
		/**
		 * Get penalty points for segment type
		 *
		 * This method assigns penalty scores to different segment types based on
		 * their specificity. Higher penalties are given to more generic segment
		 * types, which lowers their priority in route matching. This ensures
		 * that specific routes are matched before generic wildcard routes.
		 *
		 * Penalty scale (higher = less specific = lower priority):
		 * - Multi-wildcards: 200 points (least specific)
		 * - Single wildcards: 100 points
		 * - Variables: 50 points
		 * - Partial variables: 30 points
		 * - Static segments: 0 points (most specific)
		 *
		 * @param string $segmentType The segment type to get penalty for
		 * @return int Penalty points to subtract from route priority
		 */
		public function getSegmentPenalty(string $segmentType): int {
			return match ($segmentType) {
				// Multi-wildcards are least specific - highest penalty
				// They match any number of segments, making them very generic
				'multi_wildcard', 'multi_wildcard_var' => 200,
				
				// Single wildcards match any one segment - high penalty
				'single_wildcard' => 100,
				
				// Variables match one segment with optional constraints - moderate penalty
				'variable' => 50,
				
				// Partial variables have some static content - lower penalty
				'partial_variable' => 30,
				
				// Static segments are most specific - no penalty
				// They require exact matches and should have highest priority
				default => 0
			};
		}
		
		/**
		 * Checks if a route segment contains partial variables (like "v{id:int}")
		 * @param string $segment Route segment to check
		 * @return bool True if segment contains embedded variables
		 */
		public function hasPartialVariable(string $segment): bool {
			$hasVariable = preg_match('/\{[^}]+}/', $segment);
			$isCompleteVariable = !empty($segment) && $segment[0] === '{' && str_ends_with($segment, '}');
			return $hasVariable && !$isCompleteVariable;
		}
		
		/**
		 * Determines if a route segment is a variable placeholder
		 * @param string $segment Route segment to check
		 * @return bool True if the segment is a variable placeholder
		 */
		public function isVariable(string $segment): bool {
			return !empty($segment) && $segment[0] === '{' && str_ends_with($segment, '}');
		}
		
		/**
		 * Extracts the variable name from a route segment
		 * @param string $segment Route segment containing variable (e.g., "{id}", "v{path:**}", "user-{id:int}")
		 * @return string The extracted variable name (e.g., "id", "path", "id")
		 */
		public function extractVariableName(string $segment): string {
			// Handle partial segments with mixed literal text and variables
			// Use regex to find the first variable definition within braces
			if (preg_match('/\{([^}]+)}/', $segment, $matches)) {
				// Extract content from inside the first set of braces
				// For "v{path:**}" this gets "path:**"
				$variableName = $matches[1];
			} else {
				// Handle simple variable segments that are entirely wrapped in braces
				// For "{id}" this removes the surrounding braces to get "id"
				$variableName = trim($segment, '{}');
			}
			
			// Check if the variable has a type constraint (e.g., "id:int" or "path:**")
			// If not, return the variable name as-is
			if (!str_contains($variableName, ':')) {
				return $variableName;
			}
			
			// Split on the first colon to separate variable name from type constraint
			// For "path:**" this returns "path", ignoring the ":**" wildcard type
			return explode(':', $variableName, 2)[0];
		}
		
		/**
		 * Get the first segment of a route path
		 * @param string $routePath
		 * @return string
		 */
		public function getFirstSegment(string $routePath): string {
			$segments = $this->parseRoutePath($routePath);
			return $segments[0] ?? '';
		}
		
		/**
		 * Parses a route path string into clean segments for matching
		 * @param string $routePath Raw route path like '/users/{id}/posts'
		 * @return array Clean route segments like ['users', '{id}', 'posts']
		 */
		private function parseRoutePath(string $routePath): array {
			$segments = explode('/', ltrim($routePath, '/'));
			
			return array_filter($segments, function ($segment) {
				return $segment !== '';
			});
		}
	}