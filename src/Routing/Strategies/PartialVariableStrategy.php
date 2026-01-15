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
			// Branch 1: Wildcard partial variables (e.g., "prefix-{**}")
			if (!empty($segment['is_multi_wildcard'])) {
				return $this->matchWildcardPartial($segment, $context);
			}
			
			// Branch 2: Regular partial variables with compiled regex
			if (!empty($segment['compiled_regex'])) {
				return $this->matchWithRegex($segment, $context);
			}
			
			// Branch 3: Fallback to metadata-based or legacy matching
			return $this->matchWithMetadata($segment, $context);
		}
		
		/**
		 * Handle partial variables with multi-wildcard components
		 * Examples: "api-{**}", "file-{path:**}"
		 * @param array $segment The segment configuration containing literal_prefix and variable_name
		 * @param MatchingContext $context The current matching context with URL segments and variables
		 * @return MatchResult The result of the matching attempt (NO_MATCH or COMPLETE_MATCH)
		 */
		private function matchWildcardPartial(array $segment, MatchingContext $context): MatchResult {
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
		 * Match using pre-compiled regex pattern
		 * Examples: "user-{id:\d+}", "file-{name}-{ext}"
		 * @param array $segment The segment configuration containing compiled_regex and variable_names
		 * @param MatchingContext $context The current matching context with URL segments and variables
		 * @return MatchResult The result of the matching attempt (NO_MATCH or CONTINUE_MATCHING)
		 */
		private function matchWithRegex(array $segment, MatchingContext $context): MatchResult {
			// Get the current URL segment we're attempting to match against
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			// Attempt to match the current URL segment against the compiled regex
			if (!preg_match($segment['compiled_regex'], $currentUrlSegment, $matches)) {
				return MatchResult::NO_MATCH;
			}
			
			// Extract all named capture groups from the regex match
			// and store them as route variables
			foreach ($segment['variable_names'] as $varName) {
				if (isset($matches[$varName])) {
					$context->setVariable($varName, $matches[$varName]);
				}
			}
			
			// Return CONTINUE_MATCHING because we successfully matched this segment
			// but there may be more segments in the route pattern to process
			return MatchResult::CONTINUE_MATCHING;
		}
		
		/**
		 * Match using pattern metadata or legacy algorithm
		 * @param array $segment The route segment configuration containing pattern data
		 * @param MatchingContext $context The current matching context with URL information
		 * @return MatchResult The result of the matching operation
		 */
		private function matchWithMetadata(array $segment, MatchingContext $context): MatchResult {
			// Get the current URL segment from the matching context
			$currentUrlSegment = $context->getCurrentUrlSegment();
			
			// Check if we have pre-compiled pattern metadata available for optimization
			// This allows us to use faster, cached pattern matching when possible
			if (isset($segment['pattern_metadata'])) {
				// Use the optimized matching path with pre-compiled patterns
				// This should be faster and more efficient than the original method
				return $this->matchWithOptimizedMetadata($segment['pattern_metadata'], $currentUrlSegment, $context);
			}
			
			// If no pattern metadata is available, fall back to the original matching algorithm
			// This ensures backward compatibility with existing route configurations
			// and handles edge cases where pattern compilation wasn't possible
			return $this->matchWithLegacyParsing($segment, $currentUrlSegment, $context);
		}
		
		/**
		 * Optimized matching using pre-calculated pattern metadata
		 * @param array $metadata
		 * @param string $urlSegment The URL segment to match against the pattern
		 * @param MatchingContext $context Context object for storing extracted variables
		 * @return MatchResult Result indicating match success and next action
		 */
		private function matchWithOptimizedMetadata(array $metadata, string $urlSegment, MatchingContext $context): MatchResult {
			// Cache the URL segment length to avoid multiple strlen() calls
			$urlLength = strlen($urlSegment);
			
			// Perform early rejection: if the URL segment is shorter than the minimum
			// required length (prefix + suffix + at least 1 char for variable), it cannot match
			if ($urlLength < $metadata['min_length']) {
				return MatchResult::NO_MATCH;
			}
			
			// Extract pre-calculated pattern components for efficient access
			$literalPrefix = $metadata['literal_prefix'];
			$literalSuffix = $metadata['literal_suffix'];
			$prefixLength = $metadata['prefix_length'];
			$suffixLength = $metadata['suffix_length'];
			
			// Verify the URL segment starts with the expected literal prefix
			// Using substr() with exact length is faster than string comparison with longer strings
			if ($prefixLength > 0 && substr($urlSegment, 0, $prefixLength) !== $literalPrefix) {
				return MatchResult::NO_MATCH;
			}
			
			// Verify the URL segment ends with the expected literal suffix
			// Negative offset in substr() counts from the end of the string
			if ($suffixLength > 0 && substr($urlSegment, -$suffixLength) !== $literalSuffix) {
				return MatchResult::NO_MATCH;
			}
			
			// Calculate the boundaries for variable extraction
			$startPos = $prefixLength;
			$variableLength = $urlLength - $prefixLength - $suffixLength;
			
			// Ensure the variable portion has actual content
			// Variables must contain at least one character to be valid
			if ($variableLength <= 0) {
				return MatchResult::NO_MATCH;
			}
			
			// Extract the variable value from between the literal prefix and suffix
			// This is the actual dynamic content that will be passed to the route handler
			$variableValue = substr($urlSegment, $startPos, $variableLength);
			
			// Store the extracted variable in the routing context for later use
			// The variable name comes from the route pattern (e.g., "id" from "{id}")
			$context->setVariable($metadata['variable_name'], $variableValue);
			
			// Indicate successful match and that routing should continue to the next segment
			// This allows for multi-segment routes like "/user/{id}/posts/{postId}"
			return MatchResult::CONTINUE_MATCHING;
		}
		
		/**
		 * Legacy matching algorithm for backward compatibility
		 * @param array $segment
		 * @param string $currentUrlSegment
		 * @param MatchingContext $context
		 * @return MatchResult
		 */
		private function matchWithLegacyParsing(array $segment, string $currentUrlSegment, MatchingContext $context): MatchResult {
			// Fetch segment
			$original = $segment['original'];
			
			// Use regex to parse the route pattern into its components
			if (!preg_match('/^([^{]*)(\{[^}]+})(.*)$/', $original, $matches)) {
				return MatchResult::NO_MATCH;
			}
			
			// Extract info from matches
			$literalPrefix = $matches[1];
			$variablePart = $matches[2];
			$literalSuffix = $matches[3];
			
			// Validate that the URL segment starts with the required literal prefix
			if ($literalPrefix !== '' && !str_starts_with($currentUrlSegment, $literalPrefix)) {
				return MatchResult::NO_MATCH;
			}
			
			// Validate that the URL segment ends with the required literal suffix
			if ($literalSuffix !== '' && !str_ends_with($currentUrlSegment, $literalSuffix)) {
				return MatchResult::NO_MATCH;
			}
			
			// Calculate the positions to extract the variable value from the URL segment
			$startPos = strlen($literalPrefix);
			$endPos = strlen($literalSuffix) > 0 ? -strlen($literalSuffix) : null;
			
			// Extract the variable value from between the prefix and suffix
			if ($endPos !== null) {
				$variableValue = substr($currentUrlSegment, $startPos, $endPos - $startPos);
			} else {
				$variableValue = substr($currentUrlSegment, $startPos);
			}
			
			// Extract the variable name from the placeholder by removing curly braces
			$variableName = trim($variablePart, '{}');
			
			// Clean the variable name by removing type constraints
			if (str_contains($variableName, ':')) {
				$variableName = explode(':', $variableName)[0];
			}
			
			// Store the extracted variable value in the routing context
			$context->setVariable($variableName, $variableValue);
			
			// Return CONTINUE_MATCHING because we successfully matched this segment
			// but there may be more segments in the route pattern to process
			return MatchResult::CONTINUE_MATCHING;
		}
	}