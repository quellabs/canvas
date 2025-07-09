<?php
	
	namespace Quellabs\Canvas\Routing\Strategies;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	
	/**
	 * Static Segment Matching Strategy
	 *
	 * This strategy handles URL segments that must match exactly with a predefined static value.
	 * Used for fixed route components like "/users" or "/api" where no parameters are involved.
	 *
	 * Example:
	 * - Route: /users/profile
	 * - URL: /users/profile -> MATCH
	 * - URL: /users/settings -> NO_MATCH (profile segment fails)
	 */
	class StaticSegmentStrategy implements SegmentMatchingStrategyInterface {
		
		/**
		 * Matches a static segment against the current URL segment
		 *
		 * @param array $segment The route segment definition containing the expected static value
		 * @param MatchingContext $context The current matching context with URL information
		 * @return MatchResult Either NO_MATCH if segments don't match, or CONTINUE_MATCHING if they do
		 */
		public function match(array $segment, MatchingContext $context): MatchResult {
			// Get the current URL segment from the context and compare it with the expected static value
			if ($segment['original'] !== $context->getCurrentUrlSegment()) {
				// Segments don't match - this route cannot handle this URL
				return MatchResult::NO_MATCH;
			}
			
			// Segments match exactly - continue processing the next segment in the route
			return MatchResult::CONTINUE_MATCHING;
		}
	}