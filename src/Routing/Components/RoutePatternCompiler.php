<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
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
	 */
	class RoutePatternCompiler {
		
		private RouteSegmentAnalyzer $segmentAnalyzer;
		
		// Static type pattern mappings for variable validation
		private const array TYPE_PATTERNS = [
			// Numeric types
			'int'          => '\d+',
			'integer'      => '\d+',
			
			// Text types
			'alpha'        => '[a-zA-Z]+',
			'alnum'        => '[a-zA-Z0-9]+',
			'alphanumeric' => '[a-zA-Z0-9]+',
			'word'         => '\w+',
			'slug'         => '[a-zA-Z0-9-]+',
			
			// Identifiers
			'uuid'         => '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
			
			// Web-specific
			'email'        => '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
			
			// Version/Code patterns
			'hex'          => '[a-fA-F0-9]+',
			'base64'       => '[a-zA-Z0-9+/=]+',
			
			// Common business patterns
			'sku'          => '[A-Z0-9\-]+',
			'isbn'         => '\d{3}-\d{1,5}-\d{1,7}-\d{1,7}-\d{1}',
			'phone'        => '\+?[0-9\-\s\(\)]+',
			'postal'       => '[A-Z0-9\s\-]+',
			
			// Locale/Language
			'locale'       => '[a-z]{2}(_[A-Z]{2})?',
			'language'     => '[a-z]{2,3}',
			'country'      => '[A-Z]{2}',
			'currency'     => '[A-Z]{3}',
		];
		
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
		 * @return array Array of compiled segment objects with pre-processed matching information
		 */
		public function compileRoute(string $routePath): array {
			// Parse the route path into individual segments
			// e.g., "/user/{id}/posts" becomes ["user", "{id}", "posts"]
			$segments = $this->parseRoutePath($routePath);
			
			// Process each segment and compile it for optimal matching
			$compiledSegments = [];
			
			foreach ($segments as $segment) {
				// Determine the type of this segment (static, variable, wildcard, etc.)
				$type = $this->segmentAnalyzer->getSegmentType($segment);
				
				// Initialize the compiled segment structure with default values
				$compiledSegment = [
					'type'              => $type,       // Segment type for routing logic
					'original'          => $segment,    // Original segment text for reference
					'variable_name'     => null,        // Variable name if this captures a value
					'pattern'           => null,        // Regex pattern for validation
					'is_multi_wildcard' => false,       // Whether this consumes multiple segments
					'compiled_regex'    => null,        // Pre-compiled regex for partial variables
					'variable_names'    => [],          // Array of variable names for partial segments
					'literal_prefix'    => null,  // For partial variables
					'literal_suffix'    => null   // For partial variables
				];
				
				// Compile segment based on its type
				switch ($type) {
					case 'variable':
						// Handle variable segments like {id}, {slug}, {id:int}, {path:**}
						$compiledSegment['variable_name'] = $this->segmentAnalyzer->extractVariableName($segment);
						
						// Check if the variable has a type constraint (e.g., {id:int})
						if (str_contains($segment, ':')) {
							// Split variable name and type constraint
							$parts = explode(':', trim($segment, '{}'), 2);
							
							// Convert type constraint to regex pattern
							$compiledSegment['pattern'] = $this->resolveTypeToRegex($parts[1]);
							
							// Check if this is a multi-wildcard type (** or .*)
							$compiledSegment['is_multi_wildcard'] = in_array($parts[1], ['**', '.*']);
						} else {
							// Default pattern for variables without type constraints
							// Matches any characters except forward slash
							$compiledSegment['pattern'] = '[^\/]+';
						}
						
						break;
					
					case 'single_wildcard':
						// Handle anonymous single wildcard (*)
						$compiledSegment['variable_name'] = '*';
						break;
					
					case 'multi_wildcard':
					case 'multi_wildcard_var':
						// Handle multi-wildcard segments (**) or named multi-wildcards ({**})
						if ($segment === '**' || $segment === '{**}') {
							// Anonymous multi-wildcard
							$compiledSegment['variable_name'] = '**';
						} else {
							// Named multi-wildcard variable
							$compiledSegment['variable_name'] = $this->segmentAnalyzer->extractVariableName($segment);
						}
						
						$compiledSegment['is_multi_wildcard'] = true;
						break;
					
					case 'partial_variable':
						// Handle segments with mixed static text and variables
						// e.g., "user-{id}-profile" or "file.{name}.{ext}"
						$result = $this->compilePartialSegmentPattern($segment);
						
						if ($result) {
							$compiledSegment['compiled_regex'] = $result['pattern'];
							$compiledSegment['variable_names'] = $result['variables'];
							$compiledSegment['literal_prefix'] = $result['literal_prefix'] ?? null;
							$compiledSegment['literal_suffix'] = $result['literal_suffix'] ?? null;
							
							// Check if any variables are wildcards
							foreach ($result['variable_info'] as $varInfo) {
								if ($varInfo['is_wildcard']) {
									$compiledSegment['is_multi_wildcard'] = $varInfo['is_multi_wildcard'];
									$compiledSegment['variable_name'] = $varInfo['clean_name'];
									break;
								}
							}
						}
						
						break;
				}
				
				// Add the compiled segment to the result array
				$compiledSegments[] = $compiledSegment;
			}
			
			return $compiledSegments;
		}
		
		/**
		 * Takes a route segment like "/users/{id:int}/posts/{slug}" and converts it
		 * into a regex pattern for matching URLs, extracting variable names and their
		 * corresponding regex patterns.
		 * @param string $segment The route segment to compile (e.g., "/users/{id:\d+}")
		 * @return array|null Returns [$pattern, $variableNames] or null on failure
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
					$varInfo = $this->parseVariableDefinition($variableContent);
					
					// Store variable metadata for later use
					$hasFoundVariable = true;
					$variableNames[] = $varInfo['name'];
					$variableInfo[] = $varInfo;
					
					// Convert the variable definition into a regex capturing group
					// This wraps the variable pattern in parentheses for capture
					$pattern .= $this->buildVariablePattern($varInfo);
					
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
		 * Optimized regex lookup using cached patterns
		 * @param string $type The type constraint (int, alpha, uuid, etc.)
		 * @return string The corresponding regex pattern
		 */
		public function resolveTypeToRegex(string $type): string {
			// Handle wildcard types explicitly
			if ($type === '*') {
				return '[^/]*';  // Single wildcard - any chars except path separator
			}
			
			// Multi-wildcard - any chars including path separators
			if ($type === '**') {
				return '.*';
			}
			
			// Use the existing TYPE_PATTERNS for other types
			return self::TYPE_PATTERNS[$type] ?? '[^/]+';
		}
		
		/**
		 * Parses a route path string into clean segments for compilation
		 * @param string $routePath Raw route path like '/users/{id}/posts'
		 * @return array Clean route segments like ['users', '{id}', 'posts']
		 */
		public function parseRoutePath(string $routePath): array {
			// Remove leading slash and split the path into segments by '/'
			// ltrim() removes any leading '/' characters to normalize the input
			$segments = explode('/', ltrim($routePath, '/'));
			
			// Filter out empty segments that might occur from double slashes or trailing slashes
			// This ensures we only keep meaningful path segments
			return array_filter($segments, function ($segment) {
				return $segment !== '';
			});
		}
		
		/**
		 * Builds the regex pattern for a variable based on its type.
		 * @param array $varInfo Variable information containing name, regex, and type flags
		 * @return string The regex pattern for this variable
		 */
		private function buildVariablePattern(array $varInfo): string {
			$varName = $varInfo['name'];
			
			// Ensure the variable name is safe for regex
			$safeVarName = preg_replace('/[^a-zA-Z0-9_]/', '_', $varName);
			
			// Regular variable with custom or default regex
			if (!$varInfo['is_wildcard']) {
				return "(?<{$safeVarName}>{$varInfo['regex']})";
			}
			
			// Multi-wildcard (**) - matches across path segments
			if ($varInfo['is_multi_wildcard']) {
				return "(?<{$safeVarName}>.*?)";
			}
			
			// Single wildcard (*) - matches within single path segment
			return "(?<{$safeVarName}>[^/]*)"; // Direct pattern instead of using varInfo['regex']
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
			bool   $hasFoundVariable
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
		 * @return array Returns ['name' => string, 'regex' => string]
		 */
		private function parseVariableDefinition(string $content): array {
			$isWildcard = false;
			$isMultiWildcard = false;
			$cleanName = $content;
			$regex = '[^/]+'; // Default regex
			
			// Check for wildcard patterns
			if (str_ends_with($content, ':**')) {
				$isWildcard = true;
				$isMultiWildcard = true;
				$cleanName = substr($content, 0, -3); // Remove :**
				$regex = '.*'; // Multi-wildcard pattern
			} elseif (str_ends_with($content, ':*')) {
				$isWildcard = true;
				$isMultiWildcard = false;
				$cleanName = substr($content, 0, -2); // Remove :*
				// FIX: Use escaped regex pattern for single wildcard
				$regex = '[^/]*'; // FIXED: Remove backslash that was causing the issue
			} elseif ($content === '**') {
				$isWildcard = true;
				$isMultiWildcard = true;
				$cleanName = '**';
				$regex = '.*';
			} elseif ($content === '*') {
				$isWildcard = true;
				$isMultiWildcard = false;
				$cleanName = '*';
				// FIX: Use escaped regex pattern
				$regex = '[^/]*'; // FIXED: Remove backslash
			} elseif (str_contains($content, ':')) {
				// Regular typed variable
				$parts = explode(':', $content, 2);
				$cleanName = $parts[0];
				$regex = $this->resolveTypeToRegex($parts[1]);
			}
			
			return [
				'name'              => $cleanName,
				'clean_name'        => $cleanName,
				'regex'             => $regex,
				'is_wildcard'       => $isWildcard,
				'is_multi_wildcard' => $isMultiWildcard,
				'original_content'  => $content
			];
		}
	}