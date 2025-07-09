<?php
	
	namespace Quellabs\Canvas\Routing\Strategies;
	
	use Quellabs\Canvas\Routing\MatchingContext;
	use Quellabs\Canvas\Routing\MatchResult;
	
	/**
	 * Updated PartialVariableStrategy that works with the enhanced compiler.
	 */
	class PartialVariableStrategy implements SegmentMatchingStrategyInterface {
		
		/**
		 * Matches a segment that contains both literal text and variables.
		 */
		public function match(array $segment, MatchingContext $context): MatchResult {
			// Check if this segment contains a multi-wildcard
			if (!empty($segment['is_multi_wildcard']) && !empty($segment['variable_name'])) {
				return $this->matchWildcardPartialVariable($segment, $context);
			}
			
			// Handle regular partial variables
			return $this->matchRegularPartialVariable($segment, $context);
		}
		
		/**
		 * Handle partial variable segments that contain wildcards.
		 */
		private function matchWildcardPartialVariable(array $segment, MatchingContext $context): MatchResult {
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			if ($currentUrlSegment === null) {
				return MatchResult::NO_MATCH;
			}
			
			$literalPrefix = $segment['literal_prefix'] ?? '';
			$variableName = $segment['variable_name'];
			
			// Check if the URL segment starts with the required literal prefix
			if ($literalPrefix !== '' && !str_starts_with($currentUrlSegment, $literalPrefix)) {
				return MatchResult::NO_MATCH;
			}
			
			// For multi-wildcard in partial segment, capture the remainder of this segment
			// plus all remaining URL segments
			$remainingUrlSegments = $context->getRemainingUrlSegments();
			
			// Start with the part of current segment after the literal prefix
			$capturedParts = [substr($currentUrlSegment, strlen($literalPrefix))];
			
			// Add all remaining URL segments
			if (count($remainingUrlSegments) > 1) {
				$capturedParts = array_merge($capturedParts, array_slice($remainingUrlSegments, 1));
			}
			
			$capturedPath = implode('/', $capturedParts);
			
			// Store the captured path
			if ($variableName === '**') {
				$context->addToVariableArray('**', $capturedPath);
			} else {
				$context->setVariable($variableName, $capturedPath);
			}
			
			// Since we consumed all remaining segments, this is a complete match
			return MatchResult::COMPLETE_MATCH;
		}
		
		/**
		 * Handle regular partial variable segments (non-wildcard).
		 */
		private function matchRegularPartialVariable(array $segment, MatchingContext $context): MatchResult {
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			// Use compiled regex if available
			if (!empty($segment['compiled_regex'])) {
				if (preg_match($segment['compiled_regex'], $currentUrlSegment, $matches)) {
					// Extract named captures and store as variables
					foreach ($segment['variable_names'] as $varName) {
						if (isset($matches[$varName])) {
							$context->setVariable($varName, $matches[$varName]);
						}
					}
					
					return MatchResult::CONTINUE_MATCHING;
				}
				return MatchResult::NO_MATCH;
			}
			
			// Fallback for segments without compiled regex
			return $this->fallbackPartialMatch($segment, $context);
		}
		
		/**
		 * Fallback matching for partial variables without compiled regex.
		 */
		private function fallbackPartialMatch(array $segment, MatchingContext $context): MatchResult {
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			// Extract literal prefix/suffix from the original segment
			$original = $segment['original'];
			
			// Simple extraction logic for basic cases
			if (preg_match('/^([^{]*)(\{[^}]+})(.*)$/', $original, $matches)) {
				$literalPrefix = $matches[1];
				$variablePart = $matches[2];
				$literalSuffix = $matches[3];
				
				// Check prefix and suffix
				if ($literalPrefix !== '' && !str_starts_with($currentUrlSegment, $literalPrefix)) {
					return MatchResult::NO_MATCH;
				}
				
				if ($literalSuffix !== '' && !str_ends_with($currentUrlSegment, $literalSuffix)) {
					return MatchResult::NO_MATCH;
				}
				
				// Extract variable value
				$startPos = strlen($literalPrefix);
				$endPos = strlen($literalSuffix) > 0 ? -strlen($literalSuffix) : null;
				
				$variableValue = $endPos !== null ?
					substr($currentUrlSegment, $startPos, $endPos - $startPos) :
					substr($currentUrlSegment, $startPos);
				
				// Extract variable name
				$variableName = trim($variablePart, '{}');
				
				// Clean variable name (remove type constraints and wildcards)
				if (str_contains($variableName, ':')) {
					$variableName = explode(':', $variableName)[0];
				}
				
				$context->setVariable($variableName, $variableValue);
				return MatchResult::CONTINUE_MATCHING;
			}
			
			return MatchResult::NO_MATCH;
		}
	}