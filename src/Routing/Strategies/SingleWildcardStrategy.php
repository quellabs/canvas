<?php
	
	namespace Quellabs\Canvas\Routing\Strategies;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	use Quellabs\Canvas\Routing\RouteTypes;
	
	/**
	 * Single wildcard strategy for route segment matching.
	 *
	 * This strategy handles single wildcard segments in route patterns,
	 * capturing URL segments and storing them as variables in the matching context.
	 *
	 * @phpstan-import-type CompiledSegment from RouteTypes
	 */
	class SingleWildcardStrategy implements SegmentMatchingStrategyInterface {
		
		/**
		 * Matches a single wildcard segment against the current URL segment.
		 *
		 * This method captures the current URL segment and stores it either in a
		 * variable array (for '*' wildcards) or as a named variable based on the
		 * segment configuration.
		 *
		 * @param CompiledSegment $segment The route segment configuration containing variable_name
		 * @param MatchingContext $context The matching context with current URL state
		 * @return MatchResult Always returns CONTINUE_MATCHING to proceed with next segment
		 */
		public function match(array $segment, MatchingContext $context): MatchResult {
			// Get the current URL segment to match against
			$urlSegment = $context->getCurrentUrlSegment();
			
			// Check if this is a catch-all wildcard (*)
			if ($segment['variable_name'] === '*') {
				// Store in variable array for catch-all wildcards
				$context->addToVariableArray('*', $urlSegment);
			} elseif ($segment['variable_name'] !== null) {
				// Store as named variable for specific wildcards
				$context->setVariable($segment['variable_name'], $urlSegment);
			}
			
			// Always continue matching to the next segment
			return MatchResult::CONTINUE_MATCHING;
		}
	}