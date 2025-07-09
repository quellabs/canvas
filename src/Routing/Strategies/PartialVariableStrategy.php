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
		 * @param array $segment
		 * @param MatchingContext $context
		 * @return MatchResult
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
		 *
		 * This method processes URL segments that contain both literal text and wildcard variables.
		 * For example, a route pattern like "file-{name}" or "prefix-{**}" where part of the
		 * segment is literal and part is a variable that can match multiple path segments.
		 *
		 * @param array $segment The segment configuration containing literal_prefix and variable_name
		 * @param MatchingContext $context The current matching context with URL segments and variables
		 * @return MatchResult The result of the matching attempt (NO_MATCH or COMPLETE_MATCH)
		 */
		private function matchWildcardPartialVariable(array $segment, MatchingContext $context): MatchResult {
			// Get the current URL segment we're trying to match against
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			// Extract the literal prefix that must appear before the variable part
			// Example: for pattern "file-{name}", literal_prefix would be "file-"
			$literalPrefix = $segment['literal_prefix'] ?? '';
			
			// Extract the variable name that will capture the wildcard content
			// This could be a named variable like "name" or the special wildcard "**"
			$variableName = $segment['variable_name'];
			
			// Validate that the URL segment starts with the required literal prefix
			// If there's a prefix and the URL doesn't start with it, this route doesn't match
			if ($literalPrefix !== '' && !str_starts_with($currentUrlSegment, $literalPrefix)) {
				return MatchResult::NO_MATCH;
			}
			
			// For multi-wildcard patterns in partial segments, we need to capture:
			// 1. The remainder of the current segment (after the literal prefix)
			// 2. All remaining URL segments in the path
			// This allows patterns like "api-{**}" to match "api-v1/users/123"
			$remainingUrlSegments = $context->getRemainingUrlSegments();
			
			// Start building the captured content with the part of the current segment
			// that comes after the literal prefix
			// Example: for URL "file-document.pdf" with prefix "file-",
			// this captures "document.pdf"
			$capturedParts = [substr($currentUrlSegment, strlen($literalPrefix))];
			
			// Add all remaining URL segments to the captured content
			// This handles cases where the wildcard should match across multiple segments
			// Skip index 0 since that's the current segment we already processed
			if (count($remainingUrlSegments) > 1) {
				$capturedParts = array_merge($capturedParts, array_slice($remainingUrlSegments, 1));
			}
			
			// Join all captured parts with '/' to reconstruct the path portion
			// that the wildcard variable should contain
			$capturedPath = implode('/', $capturedParts);
			
			// Store the captured path in the appropriate variable storage
			// Handle the special case of double-wildcard (**) which gets stored in an array
			if ($variableName === '**') {
				// Double-wildcard variables are stored as arrays to support multiple matches
				$context->addToVariableArray('**', $capturedPath);
			} else {
				// Regular named variables are stored as single values
				$context->setVariable($variableName, $capturedPath);
			}
			
			// Since wildcard partial variables consume all remaining segments,
			// this represents a complete match of the entire remaining URL path
			return MatchResult::COMPLETE_MATCH;
		}
		
		/**
		 * Handle regular partial variable segments (non-wildcard).
		 *
		 * This method processes URL segments that contain a mix of literal text and regular
		 * variables (not wildcards). For example, a route pattern like "user-{id}" or
		 * "post-{slug}.html" where part of the segment is literal and part is a variable
		 * that matches only the current segment (not multiple segments like wildcards).
		 *
		 * The method prioritizes using pre-compiled regex patterns for performance,
		 * but falls back to alternative matching logic if regex compilation wasn't possible.
		 *
		 * @param array $segment The segment configuration containing compiled_regex and variable_names
		 * @param MatchingContext $context The current matching context with URL segments and variables
		 * @return MatchResult The result of the matching attempt (NO_MATCH or CONTINUE_MATCHING)
		 */
		private function matchRegularPartialVariable(array $segment, MatchingContext $context): MatchResult {
			// Get the current URL segment we're attempting to match against
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			// Check if we have a pre-compiled regex pattern for this segment
			// Compiled regex patterns are preferred for performance and accuracy
			// Example: pattern "user-{id}" might compile to '/^user-(\d+)$/'
			if (!empty($segment['compiled_regex'])) {
				// Attempt to match the current URL segment against the compiled regex
				// The $matches array will contain both numbered and named capture groups
				if (preg_match($segment['compiled_regex'], $currentUrlSegment, $matches)) {
					// Extract all named capture groups from the regex match
					// and store them as route variables
					foreach ($segment['variable_names'] as $varName) {
						// Check if this variable name was captured in the regex match
						// Named captures in PHP regex are accessible by their name in $matches
						if (isset($matches[$varName])) {
							// Store the captured value in the routing context
							// Example: for pattern "user-{id}" matching "user-123",
							// this stores id => "123"
							$context->setVariable($varName, $matches[$varName]);
						}
					}
					
					// Return CONTINUE_MATCHING because we successfully matched this segment
					// but there may be more segments in the route pattern to process
					return MatchResult::CONTINUE_MATCHING;
				}
				
				// If the regex didn't match, this route is not compatible with the URL
				return MatchResult::NO_MATCH;
			}
			
			// If no compiled regex is available, fall back to alternative matching logic
			// This might happen during development, for legacy patterns, or when regex
			// compilation failed for some reason
			return $this->fallbackPartialMatch($segment, $context);
		}
		
		/**
		 * Fallback matching for partial variables without compiled regex.
		 *
		 * This method provides a backup matching strategy when pre-compiled regex patterns
		 * are not available. It manually parses the route pattern to extract literal prefixes,
		 * suffixes, and variable placeholders, then matches them against the URL segment.
		 *
		 * This fallback handles basic cases like "prefix-{var}-suffix" but may not support
		 * all the advanced features available in compiled regex patterns.
		 *
		 * @param array $segment The segment configuration containing the original pattern
		 * @param MatchingContext $context The current matching context with URL segments and variables
		 * @return MatchResult The result of the matching attempt (NO_MATCH or CONTINUE_MATCHING)
		 */
		private function fallbackPartialMatch(array $segment, MatchingContext $context): MatchResult {
			// Get the current URL segment we're trying to match
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			// Get the original route pattern string for manual parsing
			// Example: "user-{id}-profile" or "file-{name}.html"
			// Note: This fallback only supports ONE variable per segment
			$original = $segment['original'];
			
			// Use regex to parse the route pattern into its components:
			// - Literal prefix (text before the variable)
			// - Variable placeholder (the {variable} part)
			// - Literal suffix (text after the variable)
			// Pattern matches: prefix + {variable} + suffix
			if (preg_match('/^([^{]*)(\{[^}]+})(.*)$/', $original, $matches)) {
				// Extract the literal text that must appear before the variable
				// Example: for "user-{id}-profile", this would be "user-"
				$literalPrefix = $matches[1];
				
				// Extract the variable placeholder including the curly braces
				// Example: for "user-{id}-profile", this would be "{id}"
				$variablePart = $matches[2];
				
				// Extract the literal text that must appear after the variable
				// Example: for "user-{id}-profile", this would be "-profile"
				$literalSuffix = $matches[3];
				
				// Validate that the URL segment starts with the required literal prefix
				// If there's a prefix and the URL doesn't start with it, no match
				if ($literalPrefix !== '' && !str_starts_with($currentUrlSegment, $literalPrefix)) {
					return MatchResult::NO_MATCH;
				}
				
				// Validate that the URL segment ends with the required literal suffix
				// If there's a suffix and the URL doesn't end with it, no match
				if ($literalSuffix !== '' && !str_ends_with($currentUrlSegment, $literalSuffix)) {
					return MatchResult::NO_MATCH;
				}
				
				// Calculate the positions to extract the variable value from the URL segment
				// Start position is after the literal prefix
				$startPos = strlen($literalPrefix);
				
				// End position is before the literal suffix (if any)
				// If no suffix, extract to the end of the string
				$endPos = strlen($literalSuffix) > 0 ? -strlen($literalSuffix) : null;
				
				// Extract the variable value from between the prefix and suffix
				// Example: for URL "user-123-profile" with pattern "user-{id}-profile",
				// this extracts "123"
				if ($endPos !== null) {
					$variableValue = substr($currentUrlSegment, $startPos, $endPos - $startPos);
				} else {
					$variableValue = substr($currentUrlSegment, $startPos);
				}
				
				// Extract the variable name from the placeholder by removing curly braces
				// Example: "{id}" becomes "id"
				$variableName = trim($variablePart, '{}');
				
				// Clean the variable name by removing type constraints and wildcards
				// Route patterns may include type hints like "{id:int}" or "{slug:string}"
				// We only want the variable name part before the colon
				if (str_contains($variableName, ':')) {
					$variableName = explode(':', $variableName)[0];
				}
				
				// Store the extracted variable value in the routing context
				// This makes it available for use in the matched route handler
				$context->setVariable($variableName, $variableValue);
				
				// Return CONTINUE_MATCHING since we successfully matched this segment
				// and there may be more segments in the route pattern to process
				return MatchResult::CONTINUE_MATCHING;
			}
			
			// If the regex pattern didn't match the route format, this indicates
			// the route pattern is malformed or uses unsupported syntax
			return MatchResult::NO_MATCH;
		}
	}