<?php
	
	namespace Quellabs\Canvas\Routing\Components;

	use Quellabs\Canvas\Exceptions\InvalidRouteDefinitionException;
	use Quellabs\Canvas\Routing\RouteTypes;
	use Quellabs\Canvas\Routing\SegmentTypes;
	use Quellabs\Canvas\Routing\TypeConstraintResolver;
	
	/**
	 * RoutePatternCompiler
	 *
	 * Handles route pattern compilation and regex generation for optimal runtime
	 * performance. Pre-processes route patterns into optimized internal representations
	 * that can be matched quickly against incoming URLs without runtime pattern parsing.
	 *
	 * Core responsibilities:
	 * - Route pattern parsing: Breaks down route strings into analyzable segments
	 * - Segment compilation: Converts each segment into structured matching data
	 * - Regex generation: Creates optimized regex patterns for complex segments
	 * - Type constraint resolution: Maps type hints to corresponding regex patterns
	 * - Variable extraction: Identifies and processes route variables and wildcards
	 * - Partial variable handling: Supports mixed static/dynamic segments
	 *
	 * Compilation process:
	 * 1. Parses route path into individual segments
	 * 2. Determines segment type (static, variable, wildcard, partial)
	 * 3. Extracts variable names and type constraints
	 * 4. Generates appropriate regex patterns for validation
	 * 5. Handles wildcard types (single *, multi **)
	 * 6. Compiles partial variables with embedded patterns
	 * 7. Stores all metadata for efficient runtime matching
	 *
	 * Supported segment types:
	 * - Static: Exact string matching (e.g., "users", "api")
	 * - Variables: Parameter extraction (e.g., "{id}", "{slug:alpha}")
	 * - Single wildcards: One segment matching (e.g., "*", "{file:*}")
	 * - Multi-wildcards: Multiple segment matching (e.g., "**", "{path:**}")
	 * - Partial variables: Mixed segments (e.g., "v{version}", "file-{name}.{ext}")
	 *
	 * Type constraint system:
	 * - Numeric: int, integer (matches digits)
	 * - Text: alpha, alnum, word, slug (character classes)
	 * - Identifiers: uuid, email, phone (structured patterns)
	 * - Business: sku, isbn, postal (domain-specific patterns)
	 * - Locale: language, country, currency (internationalization)
	 * - Custom: Extensible pattern mapping system
	 *
	 * Regex optimization:
	 * - Named capture groups for variable extraction
	 * - Efficient pattern compilation with minimal backtracking
	 * - Literal prefix/suffix extraction for partial variables
	 * - Wildcard-aware pattern generation
	 * - Error handling for malformed patterns
	 *
	 * The compiler transforms human-readable route patterns into machine-optimized
	 * matching structures, enabling fast URL resolution while supporting complex
	 * routing scenarios including nested wildcards and type validation.
	 *
	 * @phpstan-import-type CompiledSegment from RouteTypes
	 * @phpstan-type VarInfo array{
	 *     name: string,
	 *     clean_name: string,
	 *     regex: string,
	 *     is_wildcard: bool,
	 *     is_multi_wildcard: bool,
	 *     original_content: string
	 * }
	 *
	 * @phpstan-type PartialSegmentResult array{
	 *     pattern: string,
	 *     variables: list<string>,
	 *     literal_prefix: string,
	 *     literal_suffix: string,
	 *     variable_info: list<VarInfo>
	 * }
	 */
	class RoutePatternCompiler {
		
		private RouteSegmentAnalyzer $segmentAnalyzer;
		
		/**
		 * RouteSegmentAnalyzer constructor
		 * @param RouteSegmentAnalyzer $segmentAnalyzer
		 */
		public function __construct(RouteSegmentAnalyzer $segmentAnalyzer) {
			$this->segmentAnalyzer = $segmentAnalyzer;
		}
		
		/**
		 * This method transforms a route path string (e.g., "/user/{id}/posts/{slug}")
		 * into a compiled representation that can be efficiently matched against
		 * incoming URLs. Each segment is analyzed and compiled with its type,
		 * patterns, and variable information pre-determined to avoid runtime
		 * processing overhead.
		 * @param string $routePath The original route path pattern (e.g., "/user/{id}/posts")
		 * @return list<CompiledSegment> Array of compiled segment objects with pre-processed matching information
		 * @throws InvalidRouteDefinitionException If the same variable name is bound more than once,
		 *         whether within one segment ("{id}-{id}") or across separate segments ("/{id}/{id}")
		 */
		public function compileRoute(string $routePath): array {
			// A repeated variable name has no sound interpretation (which occurrence wins?),
			// whether both occurrences are in the same segment or in separate ones — so this
			// is checked once, directly against the raw path, before any segment is compiled.
			$this->assertNoDuplicateVariableNames($routePath);

			// Parse the route path into individual segments
			// e.g., "/user/{id}/posts" becomes ["user", "{id}", "posts"]
			$segments = $this->parseRoutePath($routePath);
			
			// Process each segment and compile it for optimal matching
			$compiledSegments = [];
			
			foreach ($segments as $segment) {
				$compiledSegments[] = match ($this->segmentAnalyzer->getSegmentType($segment)) {
					'variable' => $this->buildVariableSegment($segment),
					'single_wildcard' => $this->buildSingleWildcardSegment($segment),
					'multi_wildcard', 'multi_wildcard_var' => $this->buildMultiWildcardSegment($segment),
					'partial_variable' => $this->buildPartialVariableSegment($segment),
					default => $this->buildStaticSegment($segment),
				};
			}
			
			// Post-processing pass: fill in remaining_segments_count for every multi-wildcard
			// segment. This tells the strategy how many URL segments must be left unconsumed
			// so that the route segments that follow the wildcard can still be satisfied.
			// Example: for /files/**/README.md the ** segment gets remaining_segments_count = 1.
			$total = count($compiledSegments);
			
			for ($i = 0; $i < $total; $i++) {
				if (!SegmentTypes::isMultiWildcard($compiledSegments[$i])) {
					continue;
				}
				
				// Count non-multi-wildcard segments that follow this one. Each of those
				// consumes exactly one URL segment, so the wildcard must leave that many behind.
				$remaining = 0;
				
				for ($j = $i + 1; $j < $total; $j++) {
					if (!SegmentTypes::isMultiWildcard($compiledSegments[$j])) {
						$remaining++;
					}
				}
				
				/** @var CompiledSegment $updated */
				$updated = [...$compiledSegments[$i], 'remaining_segments_count' => $remaining];
				$compiledSegments[$i] = $updated;
			}

			return $compiledSegments;
		}

		/**
		 * Ensures no variable name is bound more than once anywhere in the route path —
		 * whether both occurrences are in the same segment ("{id}-{id}") or in separate
		 * segments ("/{id}/{id}"). Checked directly against the raw path string, since
		 * that's a single, segment-agnostic fact: the same "{name...}" token appears twice.
		 * @param string $routePath Raw route path, e.g. "/users/{id}/posts/{id}"
		 * @throws InvalidRouteDefinitionException If a variable name occurs more than once
		 */
		private function assertNoDuplicateVariableNames(string $routePath): void {
			if (preg_match_all('/\{([^{}]+)}/', $routePath, $matches) === 0) {
				return;
			}

			$seenGroupNames = [];

			foreach ($matches[1] as $variableContent) {
				// Strip a type/wildcard suffix, e.g. "id:int" -> "id", "path:**" -> "path"
				$name = explode(':', $variableContent, 2)[0];

				// '*' and '**' are anonymous wildcard sentinels, never a route author's chosen name
				if ($name === '*' || $name === '**') {
					continue;
				}

				// Compare sanitized names, since that's what actually becomes the regex capture
				// group: "my-id" and "my_id" both sanitize to "my_id" and collide just the same,
				// even though the raw names differ.
				$groupName = $this->sanitizeCaptureGroupName($name);

				if (isset($seenGroupNames[$groupName])) {
					throw new InvalidRouteDefinitionException(
						"Duplicate variable name \"{$name}\" in route \"{$routePath}\": " .
						"each variable in a route must have a unique name."
					);
				}

				$seenGroupNames[$groupName] = true;
			}
		}

		/**
		 * Takes a route segment like "/users/{id:int}/posts/{slug}" and converts it
		 * into a regex pattern for matching URLs, extracting variable names and their
		 * corresponding regex patterns.
		 * @param string $segment The route segment to compile (e.g., "/users/{id:\d+}")
		 * @return PartialSegmentResult|null Returns compiled pattern result or null on failure
		 */
		public function compilePartialSegmentPattern(string $segment): ?array {
			// Initialize compilation state variables
			$pattern = '';                  // The final regex pattern being built
			$position = 0;                  // Current position in the segment string
			$literalPrefix = '';            // Literal text before any variables
			$literalSuffix = '';            // Literal text after the last variable
			$variableNames = [];            // Array of variable names found in the segment
			$hasFoundVariable = false;      // Flag to track if we've encountered any variables
			$variableInfo = [];             // Detailed information about each variable
			$segmentLength = strlen($segment);
			
			// Process each character in the segment string
			while ($position < $segmentLength) {
				$currentChar = $segment[$position];
				
				// Check if we've found the start of a variable definition
				if ($currentChar === '{') {
					// Extract the complete variable content between braces
					// This handles nested braces and validates syntax
					$variableContent = $this->extractVariableContent($segment, $position);
					
					// Abort compilation if variable syntax is malformed
					// (e.g., unclosed brace, invalid nesting)
					if ($variableContent === null) {
						return null;
					}
					
					// Parse the variable definition to extract name and regex pattern
					// Example: "id:\d+" becomes ['name' => 'id', 'pattern' => '\d+']
					$variableInformation = $this->parseVariableDefinition($variableContent);

					// Store variable metadata for later use
					$hasFoundVariable = true;
					$variableNames[] = $variableInformation['name'];
					$variableInfo[] = $variableInformation;
					
					// Convert the variable definition into a regex capturing group
					// This wraps the variable pattern in parentheses for capture
					$pattern .= $this->buildVariablePattern($variableInformation);
					
					// Continue to next iteration (position is updated in extractVariableContent)
					continue;
				}
				
				// Handle literal characters (non-variable content)
				// This escapes special regex characters and tracks literal segments
				$this->processLiteralCharacter(
					$currentChar,
					$pattern,                // Add escaped character to main pattern
					$literalPrefix,          // Track prefix before first variable
					$literalSuffix,          // Track suffix after last variable
					$hasFoundVariable        // Context for prefix/suffix determination
				);
				
				// Move to the next character
				$position++;
			}
			
			// Wrap the pattern in regex delimiters and anchors
			// ^ ensures match starts at beginning, $ ensures match ends at end
			$finalPattern = '/^' . $pattern . '$/';
			
			// Validate that the generated regex pattern is syntactically correct
			// Use error suppression (@) to prevent warnings, check return value instead
			if (@preg_match($finalPattern, '') === false) {
				error_log("Invalid regex pattern generated: " . $finalPattern . " for segment: " . $segment);
				return null;
			}
			
			// Return all compilation results as an associative array
			return [
				'pattern'        => $finalPattern,    // The complete regex pattern
				'variables'      => $variableNames,   // Array of variable names in order
				'literal_prefix' => $literalPrefix,   // Static text before variables
				'literal_suffix' => $literalSuffix,   // Static text after variables
				'variable_info'  => $variableInfo     // Detailed variable metadata
			];
		}
		
		/**
		 * Parses a route path string into clean segments for compilation
		 * @param string $routePath Raw route path like '/users/{id}/posts'
		 * @return list<string> Clean route segments like ['users', '{id}', 'posts']
		 */
		public function parseRoutePath(string $routePath): array {
			// Remove leading slash and split the path into segments by '/'
			// ltrim() removes any leading '/' characters to normalize the input
			$segments = explode('/', ltrim($routePath, '/'));
			
			// Filter out empty segments that might occur from double slashes or trailing slashes
			// array_values() re-indexes the array to maintain list<string> guarantee
			return array_values(array_filter($segments, function ($segment) {
				return $segment !== '';
			}));
		}
		
		
		/**
		 * Build a CompiledSegment for a static (literal) path segment.
		 * @param string $segment The original segment text
		 * @return CompiledSegment
		 */
		private function buildStaticSegment(string $segment): array {
			return [
				'type'                     => 'static',
				'original'                 => $segment,
				'variable_name'            => null,  // No capture — static segments match literally
				'pattern'                  => null,  // No regex needed — equality check suffices
				'is_multi_wildcard'        => false,
				'compiled_regex'           => null,  // Partial-variable field; unused here
				'variable_names'           => [],    // Partial-variable field; unused here
				'literal_prefix'           => null,  // Partial-variable field; unused here
				'literal_suffix'           => null,  // Partial-variable field; unused here
				'remaining_segments_count' => 0,
			];
		}
		
		/**
		 * Build a CompiledSegment for a variable segment like {id}, {slug:alpha}, {path:**}
		 * @param string $segment The original segment text
		 * @return CompiledSegment
		 */
		private function buildVariableSegment(string $segment): array {
			$variableName = $this->segmentAnalyzer->extractVariableName($segment);
			
			// Typed variable (e.g. {id:int}, {path:**})
			if (str_contains($segment, ':')) {
				$parts = explode(':', trim($segment, '{}'), 2);
				$pattern = TypeConstraintResolver::resolveTypeToRegex($parts[1]);
				$isMultiWildcard = in_array($parts[1], ['**', '.*'], true); // {path:**} behaves like a multi-wildcard
			} else {
				// Untyped variable: matches any single segment
				$pattern = '[^\\/]+';
				$isMultiWildcard = false;
			}
			
			return [
				'type'                     => 'variable',
				'original'                 => $segment,
				'variable_name'            => $variableName,
				'pattern'                  => $pattern,           // Validated against this regex at match time
				'is_multi_wildcard'        => $isMultiWildcard,
				'compiled_regex'           => null,               // Partial-variable field; unused here
				'variable_names'           => [],                 // Partial-variable field; unused here
				'literal_prefix'           => null,               // Partial-variable field; unused here
				'literal_suffix'           => null,               // Partial-variable field; unused here
				'remaining_segments_count' => 0,
			];
		}
		
		/**
		 * Build a CompiledSegment for a single-wildcard segment (*)
		 * @param string $segment The original segment text
		 * @return CompiledSegment
		 */
		private function buildSingleWildcardSegment(string $segment): array {
			return [
				'type'                     => 'single_wildcard',
				'original'                 => $segment,
				'variable_name'            => '*',    // Sentinel; strategy discards anonymous wildcards
				'pattern'                  => null,   // Strategy uses a hardcoded [^/]+ — no stored pattern needed
				'is_multi_wildcard'        => false,
				'compiled_regex'           => null,   // Partial-variable field; unused here
				'variable_names'           => [],     // Partial-variable field; unused here
				'literal_prefix'           => null,   // Partial-variable field; unused here
				'literal_suffix'           => null,   // Partial-variable field; unused here
				'remaining_segments_count' => 0,
			];
		}
		
		/**
		 * Build a CompiledSegment for a multi-wildcard segment (** or named {path:**})
		 * @param string $segment The original segment text
		 * @return CompiledSegment
		 */
		private function buildMultiWildcardSegment(string $segment): array {
			// Anonymous multi-wildcard: strategy discards the capture
			if (($segment === '**' || $segment === '{**}')) {
				$variableName = '**';
			} else {
				$variableName = $this->segmentAnalyzer->extractVariableName($segment);
			}
			
			if (str_ends_with($segment, ':**}') || str_ends_with($segment, ':.*}')) {
				$type = SegmentTypes::MULTI_WILDCARD_VAR;
			} else {
				$type = SegmentTypes::MULTI_WILDCARD;
			}
			
			return [
				'type'                     => $type,
				'original'                 => $segment,
				'variable_name'            => $variableName,
				'pattern'                  => null,   // Strategy matches .* unconditionally — no stored pattern needed
				'is_multi_wildcard'        => true,
				'compiled_regex'           => null,   // Partial-variable field; unused here
				'variable_names'           => [],     // Partial-variable field; unused here
				'literal_prefix'           => null,   // Partial-variable field; unused here
				'literal_suffix'           => null,   // Partial-variable field; unused here
				'remaining_segments_count' => 0,  // Filled in by compileRoute() post-processing pass
			];
		}
		
		/**
		 * Build a CompiledSegment for a partial-variable segment like "user-{id}-profile"
		 * @param string $segment The original segment text
		 * @return CompiledSegment
		 */
		private function buildPartialVariableSegment(string $segment): array {
			// Defaults used when compilePartialSegmentPattern() returns null (malformed segment).
			$compiledRegex = null;  // Full regex for matching the mixed segment (e.g. /^v(\d+)$/)
			$variableNames = [];    // Ordered list of variable names for capture extraction
			$literalPrefix = null;  // Static text before the first variable (e.g. "v" in "v{ver}")
			$literalSuffix = null;  // Static text after the last variable (e.g. ".json" in "{name}.json")
			$isMultiWildcard = false;
			$variableName = null;  // Set only when a wildcard variable is present in the segment

			$result = $this->compilePartialSegmentPattern($segment);

			if ($result !== null) {
				$compiledRegex = $result['pattern'];
				$variableNames = $result['variables'];
				$literalPrefix = $result['literal_prefix'];
				$literalSuffix = $result['literal_suffix'];

				// Promote wildcard flags from the first wildcard variable found, if any.
				// Partial wildcard segments are unusual but valid (e.g. "prefix{path:**}").
				foreach ($result['variable_info'] as $varInfo) {
					if ($varInfo['is_wildcard']) {
						$isMultiWildcard = $varInfo['is_multi_wildcard'];
						$variableName = $varInfo['clean_name'];
						break;
					}
				}
			}

			return [
				'type'                     => 'partial_variable',
				'original'                 => $segment,
				'variable_name'            => $variableName,
				'pattern'                  => null,              // Unused: matching uses compiled_regex instead
				'is_multi_wildcard'        => $isMultiWildcard,
				'compiled_regex'           => $compiledRegex,
				'variable_names'           => $variableNames,
				'literal_prefix'           => $literalPrefix,
				'literal_suffix'           => $literalSuffix,
				'remaining_segments_count' => 0,
			];
		}

		/**
		 * Builds the regex pattern for a variable based on its type.
		 * @param VarInfo $varInfo Variable information containing name, regex, and type flags
		 * @return string The regex pattern for this variable
		 */
		private function buildVariablePattern(array $varInfo): string {
			// Ensure the variable name is safe for regex
			$safeVarName = $this->sanitizeCaptureGroupName($varInfo['name']);

			// Regular variable with custom or default regex
			if (!$varInfo['is_wildcard']) {
				return "(?<{$safeVarName}>{$varInfo['regex']})";
			}
			
			// Multi-wildcard (**) - matches across path segments
			if ($varInfo['is_multi_wildcard']) {
				return "(?<{$safeVarName}>.*?)";
			}
			
			// Single wildcard (*) - matches within single path segment
			return "(?<{$safeVarName}>[^\/]*)"; // Direct pattern instead of using varInfo['regex']
		}

		/**
		 * Sanitizes a variable name into a valid PCRE named-capture-group name.
		 * Used both to build each group and to detect collisions between two
		 * variables that would otherwise produce the same group name.
		 * @param string $name Raw variable name
		 * @return string Name safe for use in (?<name>...)
		 */
		private function sanitizeCaptureGroupName(string $name): string {
			return preg_replace('/[^a-zA-Z0-9_]/', '_', $name) ?? $name;
		}

		/**
		 * Processes a literal character and updates the pattern and prefix/suffix tracking.
		 * @param string $char The literal character to process
		 * @param string &$pattern The pattern being built (passed by reference)
		 * @param string &$literalPrefix The literal prefix (passed by reference)
		 * @param string &$literalSuffix The literal suffix (passed by reference)
		 * @param bool $hasFoundVariable Whether we've encountered a variable yet
		 */
		private function processLiteralCharacter(
			string $char,
			string &$pattern,
			string &$literalPrefix,
			string &$literalSuffix,
			bool $hasFoundVariable
		): void {
			// Escape special regex characters
			$pattern .= preg_quote($char, '/');
			
			// Track literal parts for potential optimization
			if (!$hasFoundVariable) {
				$literalPrefix .= $char;
			} else {
				$literalSuffix .= $char;
			}
		}
		
		/**
		 * Extracts variable content from between braces, handling nested braces
		 * @param string $segment The full segment string
		 * @param int &$position Current position (passed by reference)
		 * @return string|null Variable content or null if braces are unbalanced
		 */
		private function extractVariableContent(string $segment, int &$position): ?string {
			// Cache segment length for performance
			$segmentLength = strlen($segment);
			
			// Move past the opening brace '{'
			$position++;
			
			// Track nesting depth to handle nested braces correctly
			$braceDepth = 1;
			
			// Accumulate the content between braces
			$content = '';
			
			// Process characters until we reach the end or close all braces
			while ($position < $segmentLength && $braceDepth > 0) {
				// Check for opening brace - increases nesting depth
				// Check for closing brace - decreases nesting depth
				if ($segment[$position] === '{') {
					$braceDepth++;
				} elseif ($segment[$position] === '}') {
					$braceDepth--;
				}
				
				// Only add character to content if we're still inside braces
				// This excludes the final closing brace from the content
				if ($braceDepth > 0) {
					$content .= $segment[$position];
				}
				
				// Move to the next character
				$position++;
			}
			
			// If braces weren't properly balanced, return null (syntax error)
			if ($braceDepth !== 0) {
				return null;
			}
			
			// Return the extracted content (without the surrounding braces)
			return $content;
		}
		
		/**
		 * Parses variable definition to extract name and type
		 * @param string $content The variable content (without braces)
		 * @return VarInfo Returns ['name' => string, 'regex' => string, ...]
		 */
		private function parseVariableDefinition(string $content): array {
			// Handle special wildcard cases first (* and **)
			if (in_array($content, ['*', '**'])) {
				return $this->buildSpecialWildcardDefinition($content);
			}
			
			// Handle suffixed wildcards (:* and :**)
			if (str_ends_with($content, ':*') || str_ends_with($content, ':**')) {
				return $this->buildSuffixedWildcardDefinition($content);
			}
			
			// Handle typed variables (contains :)
			if (str_contains($content, ':')) {
				return $this->buildTypedVariableDefinition($content);
			}
			
			// Simple variable without type constraints
			return [
				'name'              => $content,
				'clean_name'        => $content,
				'regex'             => '[^\/]+',
				'is_wildcard'       => false,
				'is_multi_wildcard' => false,
				'original_content'  => $content
			];
		}
		
		/**
		 * Builds configuration for special wildcard patterns (* and **)
		 *
		 * This method creates the configuration for pure wildcard patterns:
		 * - '*' matches any characters except forward slashes (single segment)
		 * - '**' matches any characters including forward slashes (multiple segments)
		 *
		 * @param string $content The wildcard content (* or **)
		 * @return VarInfo The wildcard configuration
		 */
		private function buildSpecialWildcardDefinition(string $content): array {
			// Define wildcard patterns and their corresponding regex patterns
			$wildcards = [
				'**' => ['regex' => '.*', 'multi' => true],        // Multi-segment wildcard
				'*'  => ['regex' => '[^\/]*', 'multi' => false]    // Single-segment wildcard
			];
			
			$config = $wildcards[$content];
			
			return [
				'name'              => $content,
				'clean_name'        => $content,
				'regex'             => $config['regex'],
				'is_wildcard'       => true,
				'is_multi_wildcard' => $config['multi'],
				'original_content'  => $content
			];
		}
		
		/**
		 * Builds configuration for suffixed wildcard patterns (:* and :**)
		 *
		 * This method creates configuration for named parameters with wildcard suffixes:
		 * - 'name:*' creates a named parameter that matches single segments
		 * - 'name:**' creates a named parameter that matches multiple segments
		 *
		 * @param string $content The suffixed wildcard content (e.g., "name:*" or "path:**")
		 * @return VarInfo The wildcard configuration
		 */
		private function buildSuffixedWildcardDefinition(string $content): array {
			// Define suffix patterns with their properties
			$suffixes = [
				':**' => ['length' => 3, 'regex' => '.*', 'multi' => true],        // Multi-segment named wildcard
				':*'  => ['length' => 2, 'regex' => '[^\/]*', 'multi' => false]    // Single-segment named wildcard
			];
			
			// Find the matching suffix
			foreach ($suffixes as $suffix => $config) {
				if (str_ends_with($content, $suffix)) {
					$name = substr($content, 0, -$config['length']);
					
					return [
						'name'              => $name,
						'clean_name'        => $name,
						'regex'             => $config['regex'],
						'is_wildcard'       => true,
						'is_multi_wildcard' => $config['multi'],
						'original_content'  => $content
					];
				}
			}
			
			// Should never reach here given the calling conditions, but return safe default
			return [
				'name'              => $content,
				'clean_name'        => $content,
				'regex'             => '[^\/]+',
				'is_wildcard'       => false,
				'is_multi_wildcard' => false,
				'original_content'  => $content
			];
		}
		
		/**
		 * This method processes parameters with type constraints in the format 'name:type'.
		 * @param string $content The route segment content containing the typed parameter
		 * @return VarInfo
		 */
		private function buildTypedVariableDefinition(string $content): array {
			// Split content into name and type parts
			$parts = explode(':', $content, 2);
			
			return [
				'name'              => $parts[0],
				'clean_name'        => $parts[0],
				'regex'             => TypeConstraintResolver::resolveTypeToRegex($parts[1]),
				'is_wildcard'       => false,
				'is_multi_wildcard' => false,
				'original_content'  => $content
			];
		}
	}