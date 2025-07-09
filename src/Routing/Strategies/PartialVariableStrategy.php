<?php
	
	namespace Quellabs\Canvas\Routing\Strategies;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	
	/**
	 * Strategy for matching URL segments containing partial variables.
	 *
	 * This strategy handles route segments that contain variable placeholders
	 * mixed with static text (e.g., "user-{id}" or "page-{slug}.html").
	 * It uses pre-compiled regular expressions to extract variable values
	 * from the URL segment.
	 */
	class PartialVariableStrategy implements SegmentMatchingStrategyInterface {
		
		/**
		 * Attempts to match a URL segment against a route segment pattern.
		 *
		 * @param array $segment The route segment configuration containing:
		 *                      - 'compiled_regex': Pre-compiled regex pattern
		 *                      - 'variable_names': Array of variable names to extract
		 * @param MatchingContext $context The current matching context with URL data
		 * @return MatchResult Result indicating whether matching should continue or stop
		 */
		public function match(array $segment, MatchingContext $context): MatchResult {
			// Get the pre-compiled regex pattern for this segment
			$pattern = $segment['compiled_regex'];
			
			// Get the list of variable names that should be extracted
			$variableNames = $segment['variable_names'];
			
			// Get the current URL segment to match against
			$urlSegment = $context->getCurrentUrlSegment();
			
			// Attempt to match the URL segment using the pre-compiled regex
			if (preg_match($pattern, $urlSegment, $matches)) {
				// Successfully matched - extract all captured variables
				foreach ($variableNames as $name) {
					// Check if this variable was captured in the regex match
					if (isset($matches[$name])) {
						// Store the extracted variable value in the context
						$context->setVariable($name, $matches[$name]);
					}
				}
				
				// Signal that matching was successful and should continue
				return MatchResult::CONTINUE_MATCHING;
			}
			
			// Pattern didn't match - this route segment is not compatible
			return MatchResult::NO_MATCH;
		}
	}