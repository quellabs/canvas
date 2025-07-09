<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	/**
	 * RoutePatternCompiler
	 *
	 * Handles route pattern compilation and regex generation for optimal runtime performance.
	 * This class pre-processes route patterns into optimized internal representations that
	 * can be matched quickly against incoming URLs without runtime pattern parsing.
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
		 * Pre-compile route patterns for faster matching
		 *
		 * This method transforms a route path string (e.g., "/user/{id}/posts/{slug}")
		 * into a compiled representation that can be efficiently matched against
		 * incoming URLs. Each segment is analyzed and compiled with its type,
		 * patterns, and variable information pre-determined to avoid runtime
		 * processing overhead.
		 *
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
		 * Compiles a route segment with inline variables into a regex pattern.
		 *
		 * Takes a route segment like "/users/{id:\d+}/posts/{slug}" and converts it
		 * into a regex pattern for matching URLs, extracting variable names and their
		 * corresponding regex patterns.
		 *
		 * @param string $segment The route segment to compile (e.g., "/users/{id:\d+}")
		 * @return array|null Returns [$pattern, $variableNames] or null on failure
		 */
		public function compilePartialSegmentPattern(string $segment): ?array {
			$pattern = '';
			$position = 0;
			$literalPrefix = '';
			$literalSuffix = '';
			$variableNames = [];
			$hasFoundVariable = false;
			$variableInfo = [];
			$segmentLength = strlen($segment);
			
			// Process each character in the segment
			while ($position < $segmentLength) {
				$currentChar = $segment[$position];
				
				if ($currentChar === '{') {
					// Found start of variable definition - extract complete variable content
					$variableContent = $this->extractVariableContent($segment, $position);
					
					// Skip route in case of malformed variable syntax (e.g., unclosed brace)
					if ($variableContent === null) {
						return null;
					}
					
					// Parse variable definition to extract name and regex pattern
					$varInfo = $this->parseVariableDefinition($variableContent);
					
					// Store variable information
					$hasFoundVariable = true;
					$variableNames[] = $varInfo['name'];
					$variableInfo[] = $varInfo;
					
					// Build a regex pattern based on variable type
					$pattern .= $this->buildVariablePattern($varInfo);
					
					// Next iteration
					continue;
				}
				
				// Handle literal character
				$this->processLiteralCharacter(
					$currentChar,
					$pattern,
					$literalPrefix,
					$literalSuffix,
					$hasFoundVariable
				);
				
				$position++;
			}
			
			// Return compiled pattern and variable names
			return [
				'pattern'        => '/^' . $pattern . '$/',
				'variables'      => $variableNames,
				'literal_prefix' => $literalPrefix,
				'literal_suffix' => $literalSuffix,
				'variable_info'  => $variableInfo
			];
		}
		
		/**
		 * Optimized regex lookup using cached patterns
		 * @param string $type The type constraint (int, alpha, uuid, etc.)
		 * @return string The corresponding regex pattern
		 */
		public function resolveTypeToRegex(string $type): string {
			return self::TYPE_PATTERNS[$type] ?? '[^\/]+';
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
			$escapedName = preg_quote($varInfo['name'], '/');
			
			if (!$varInfo['is_wildcard']) {
				// Regular variable with custom or default regex
				return "(?<{$escapedName}>{$varInfo['regex']})";
			}
			
			if ($varInfo['is_multi_wildcard']) {
				// Multi-wildcard (**) - matches across path segments
				// Note: In partial segments, this requires special handling in the router
				return "(?<{$escapedName}>.*?)";
			}
			
			// Single wildcard (*) - matches within single path segment
			return "(?<{$escapedName}>[^/]*)";
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
			$regex = '[^\/]+';
			
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
				$regex = '[^\/]*'; // Single wildcard pattern
			} elseif ($content === '**') {
				$isWildcard = true;
				$isMultiWildcard = true;
				$cleanName = '**';
				$regex = '.*';
			} elseif ($content === '*') {
				$isWildcard = true;
				$isMultiWildcard = false;
				$cleanName = '*';
				$regex = '[^\/]*';
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