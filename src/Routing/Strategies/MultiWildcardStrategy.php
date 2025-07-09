<?php
	
	namespace Quellabs\Canvas\Routing\Strategies;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	
	/**
	 * Multi-wildcard routing strategy that matches multiple URL segments.
	 *
	 * This strategy handles route segments that can match multiple path segments
	 * (e.g., "**" wildcards). It calculates how many segments to consume based on
	 * the remaining route structure and captures the matched segments as a path string.
	 */
	class MultiWildcardStrategy implements SegmentMatchingStrategyInterface {
		
		/**
		 * Matches a multi-wildcard segment against the URL.
		 *
		 * This method determines how many URL segments should be consumed by the wildcard
		 * based on the remaining route segments that need to be matched after this wildcard.
		 *
		 * @param array $segment The route segment containing wildcard information
		 * @param MatchingContext $context The current matching context with URL and route state
		 * @return MatchResult The result of the matching attempt
		 */
		public function match(array $segment, MatchingContext $context): MatchResult {
			// Get the remaining segments in both the route definition and the URL
			$remainingRouteSegments = $context->getRemainingRouteSegments();
			$remainingUrlSegments = $context->getRemainingUrlSegments();
			
			// Calculate how many segments this wildcard should consume
			if (count($remainingRouteSegments) > 0) {
				// There are more route segments after this wildcard that need to be matched
				
				// Ensure we have enough URL segments to satisfy both the wildcard and remaining route
				if (count($remainingUrlSegments) < count($remainingRouteSegments)) {
					// Not enough URL segments to match the remaining route structure
					return MatchResult::NO_MATCH;
				}
				
				// Calculate segments to consume: leave enough for the remaining route segments
				$segmentsToConsume = count($remainingUrlSegments) - count($remainingRouteSegments);
				$consumedSegments = array_slice($remainingUrlSegments, 0, $segmentsToConsume);
				
				// Advance the URL index to skip the consumed segments
				// Note: -1 because advance() will increment by 1 additional step
				$context->advanceUrl($segmentsToConsume - 1);
			} else {
				// No more route segments after this wildcard, so consume all remaining URL segments
				$consumedSegments = $remainingUrlSegments;
			}
			
			// Convert the consumed segments back into a path string
			$capturedPath = implode('/', $consumedSegments);
			
			// Store the captured path in the appropriate variable
			if ($segment['variable_name'] === '**') {
				// Special handling for the generic "**" wildcard - store in array
				$context->addToVariableArray('**', $capturedPath);
			} else {
				// Named wildcard - store as a regular variable
				$context->setVariable($segment['variable_name'], $capturedPath);
			}
			
			// Signal that matching should continue with the next route segment
			return MatchResult::CONTINUE_MATCHING;
		}
	}