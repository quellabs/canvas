<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\Canvas\Routing\SegmentTypes;
	
	/**
	 * RouteSegmentAnalyzer
	 *
	 * Handles URL classification and segment analysis for route matching optimization.
	 * Analyzes route patterns to determine segment types, calculate route priorities,
	 * and extract variable information for efficient routing decisions.
	 *
	 * Core responsibilities:
	 * - Segment classification: Determines the type of each route segment
	 * - Priority calculation: Assigns specificity scores for optimal matching order
	 * - Route categorization: Classifies entire routes for indexing strategies
	 * - Variable detection: Identifies parameters, wildcards, and partial variables
	 * - Pattern analysis: Evaluates route complexity for performance optimization
	 * - Path parsing: Breaks down route strings into processable segments
	 *
	 * Segment type classification:
	 * - Static: Exact string matches requiring no processing
	 * - Variable: Single parameters with optional type constraints
	 * - Single wildcard: Matches one segment with flexible content
	 * - Multi-wildcard: Matches multiple segments for path capturing
	 * - Partial variable: Mixed static/dynamic content within single segments
	 * - Multi-wildcard variable: Named multi-segment capturing
	 *
	 * Priority calculation algorithm:
	 * - Base score: Starting priority value
	 * - Static bonus: Higher scores for exact-match segments
	 * - Variable penalty: Reduced scores for dynamic segments
	 * - Wildcard penalty: Significant reduction for catch-all patterns
	 * - Length bonus: Slight preference for longer, more specific routes
	 * - Full static bonus: Maximum priority for completely static routes
	 *
	 * Route classification for indexing:
	 * - Static routes: No variables or wildcards, fastest matching
	 * - Dynamic routes: Contains variables but predictable structure
	 * - Wildcard routes: Contains catch-all patterns, requires special handling
	 *
	 * Analysis features:
	 * - Variable name extraction from parameter syntax
	 * - Type constraint identification and processing
	 * - Wildcard pattern recognition (*, **, named variants)
	 * - Partial variable detection for complex segment patterns
	 * - Route complexity assessment for performance optimization
	 *
	 * The analyzer provides the intelligence needed for the routing system to make
	 * optimal decisions about indexing strategies, matching algorithms, and priority
	 * ordering to ensure the most specific routes are matched first while maintaining
	 * high performance across different route pattern complexities.
	 */
	class RouteSegmentAnalyzer {
		
		/**
		 * Determine the type of route segment
		 * @param string $segment
		 * @return string
		 */
		public function getSegmentType(string $segment): string {
			// Check in order of specificity
			if ($segment === '**') {
				return SegmentTypes::MULTI_WILDCARD;
			}
			
			if ($segment === '*') {
				return SegmentTypes::SINGLE_WILDCARD;
			}
			
			// Partial variables (mixed static/variable)
			if ($this->hasPartialVariable($segment) && !$this->isVariable($segment)) {
				return SegmentTypes::PARTIAL_VARIABLE;
			}
			
			// Named multi-wildcards
			if (str_ends_with($segment, ':**}') || str_ends_with($segment, ':.*}')) {
				return SegmentTypes::MULTI_WILDCARD_VAR;
			}
			
			// Regular variables
			if (!empty($segment) && $segment[0] === '{') {
				return SegmentTypes::VARIABLE;
			}
			
			// Fallback to static (should never reach here due to the static checker)
			return SegmentTypes::STATIC;
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
			$staticCount = 0;
			$totalPenalty = 0;
			
			// Analyze each segment to determine its impact on priority
			foreach ($segments as $segment) {
				// Determine the segment type (static, variable, wildcard, etc.)
				$segmentType = $this->getSegmentType($segment);
				
				// Apply type-specific penalty based on how generic the segment is
				// Special handling for partial variables with multi-wildcards
				if ($segmentType === SegmentTypes::PARTIAL_VARIABLE &&
					(str_contains($segment, ':**') || str_contains($segment, ':.*'))) {
					$totalPenalty += 200; // Treat as multi-wildcard
				} else {
					$totalPenalty += $this->getSegmentPenalty($segmentType);
				}
				
				if ($segmentType === SegmentTypes::STATIC) {
					$staticCount++;
				}
			}
			
			// Apply calculated penalties to reduce priority for generic segments
			$priority -= $totalPenalty;
			
			// Bonus points for static segments (20 points each)
			// Static segments make routes more specific and should be prioritized
			$priority += $staticCount * 20;
			
			// Small bonus for longer routes (5 points per segment)
			// Longer routes are generally more specific than shorter ones
			$priority += $segmentCount * 5;
			
			// Special bonus for completely static routes (no variables/wildcards)
			// These are the most specific possible and should always match first
			if ($totalPenalty === 0) {
				$priority += 100;
			}
			
			return $priority;
		}
		
		/**
		 * Classify route type for indexing
		 * @param array $route
		 * @return string
		 */
		public function classifyRoute(array $route): string {
			foreach ($route['compiled_pattern'] as $segment) {
				// Wildcards have highest precedence
				if (SegmentTypes::isWildcard($segment) || SegmentTypes::isMultiWildcard($segment)) {
					return 'wildcard';
				}
				
				// Variables make it dynamic
				if (SegmentTypes::hasVariables($segment)) {
					return 'dynamic';
				}
			}
			
			return 'static';
		}
		
		/**
		 * Get penalty points for segment type
		 * @param string $segmentType
		 * @return int
		 */
		public function getSegmentPenalty(string $segmentType): int {
			return match ($segmentType) {
				// Multi-wildcards are least specific - highest penalty
				// They match any number of segments, making them very generic
				SegmentTypes::MULTI_WILDCARD, SegmentTypes::MULTI_WILDCARD_VAR => 200,
				
				// Single wildcards match any one segment - high penalty
				SegmentTypes::SINGLE_WILDCARD => 100,
				
				// Variables match one segment with optional constraints - moderate penalty
				SegmentTypes::VARIABLE => 50,
				
				// Partial variables have some static content - lower penalty
				SegmentTypes::PARTIAL_VARIABLE => 30,
				
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
			// Check if the segment contains any variable pattern (text within curly braces)
			$hasVariable = preg_match('/\{[^}]+}/', $segment);
			
			// Determine if the entire segment is a complete variable
			// A complete variable starts with '{' and ends with '}'
			$isCompleteVariable = !empty($segment) && $segment[0] === '{' && str_ends_with($segment, '}');
			
			// Return true only if segment has variables but is NOT a complete variable
			// This identifies partial variables like "user{id}" or "v{id:int}"
			// but excludes complete variables like "{id}" or "{name:string}"
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
		 * @param string $segment Route segment containing variable (e.g., "{id}", "v{path:**}"
		 * @return string The extracted variable name (e.g., "id", "path", "id")
		 */
		public function extractVariableName(string $segment): string {
			// Handle simple variable segments that are entirely wrapped in braces
			// For "{id}" this removes the surrounding braces to get "id"
			$variableName = trim($segment, '{}');
			
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
		 * Get first segment of route path
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
			return array_filter($segments, fn($segment) => $segment !== '');
		}
	}