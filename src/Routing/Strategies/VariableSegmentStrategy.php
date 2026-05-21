<?php
	
	namespace Quellabs\Canvas\Routing\Strategies;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	use Quellabs\Canvas\Routing\RouteTypes;
	
	/**
	 * Strategy for matching variable segments in URL routing.
	 *
	 * This strategy handles dynamic URL segments that capture values into variables.
	 * It supports both single-segment variables (e.g., {id}) and multi-wildcard
	 * variables (e.g., {path*}) that can match multiple segments.
	 *
	 * @phpstan-import-type CompiledSegment from RouteTypes
	 */
	class VariableSegmentStrategy implements SegmentMatchingStrategyInterface {
		
		/**
		 * Matches a variable segment against the current URL segment(s).
		 *
		 * @param CompiledSegment $segment The segment configuration containing:
		 *  - 'variable_name': The name of the variable to store the captured value
		 *  - 'pattern': Optional regex pattern to validate the segment
		 *  - 'is_multi_wildcard': Boolean indicating if this captures multiple segments
		 * @param MatchingContext $context The current matching context with URL segments and variables
		 * @return MatchResult The result of the matching attempt
		 */
		public function match(array $segment, MatchingContext $context): MatchResult {
			// Extract configuration from the segment definition
			$variableName = $segment['variable_name'];
			$pattern = $segment['pattern'];
			
			// Handle multi-wildcard variables that capture remaining URL segments
			if ($segment['is_multi_wildcard'] ?? false) {
				// Get all remaining URL segments
				$remainingSegments = $context->getRemainingUrlSegments();
				
				// Join all remaining segments with '/' and store as variable value
				$capturedValue = implode('/', $remainingSegments);
				
				if ($variableName !== null) {
					$context->setVariable($variableName, $capturedValue);
				}
				
				// Multi-wildcard consumes all remaining segments, so matching is complete
				return MatchResult::COMPLETE_MATCH;
			}
			
			// Handle regular single-segment variables
			$urlSegment = $context->getCurrentUrlSegment();
			
			// Validate the URL segment against the pattern if one is specified
			// Use the pattern as-is since it's already a valid regex from the route parser
			// Use ~ as delimiter instead of / to avoid conflicts with forward slashes in the pattern
			if (
				$pattern !== null &&
				$pattern !== '' &&
				$pattern !== '*' &&
				!preg_match('~^' . $pattern . '$~', $urlSegment)
			) {
				// Pattern validation failed
				return MatchResult::NO_MATCH;
			}
			
			// Store the captured URL segment value in the variable
			if ($variableName !== null) {
				$context->setVariable($variableName, $urlSegment);
			}
			
			// Single segment matched successfully, continue with next segment
			return MatchResult::CONTINUE_MATCHING;
		}
	}