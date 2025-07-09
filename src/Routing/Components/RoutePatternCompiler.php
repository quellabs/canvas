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
			'float'        => '\d+\.\d+',
			'decimal'      => '\d+\.\d+',
			'number'       => '\d+(\.\d+)?',
			
			// Text types
			'alpha'        => '[a-zA-Z]+',
			'alnum'        => '[a-zA-Z0-9]+',
			'alphanumeric' => '[a-zA-Z0-9]+',
			'word'         => '\w+',
			'slug'         => '[a-zA-Z0-9-]+',
			
			// Identifiers
			'uuid'         => '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
			
			// Date/Time
			'date'         => '\d{4}-\d{2}-\d{2}',
			'year'         => '\d{4}',
			'month'        => '(0[1-9]|1[0-2])',
			'day'          => '(0[1-9]|[12]\d|3[01])',
			'time'         => '\d{2}:\d{2}(:\d{2})?',
			
			// Web-specific
			'email'        => '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
			'domain'       => '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
			'url'          => 'https?://[^\s/$.?#].[^\s]*',
			'path'         => '[a-zA-Z0-9\-_.\/]+',
			'filename'     => '[a-zA-Z0-9\-_.]+',
			
			// Version/Code patterns
			'version'      => 'v?\d+\.\d+(\.\d+)?',
			'semver'       => '\d+\.\d+\.\d+(-[a-zA-Z0-9\-]+)?',
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
		public function preCompileRoute(string $routePath): array {
			// Parse the route path into individual segments
			// e.g., "/user/{id}/posts" becomes ["user", "{id}", "posts"]
			$segments = $this->parseRoutePath($routePath);
			$compiledSegments = [];
			
			// Process each segment and compile it for optimal matching
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
					'variable_names'    => []           // Array of variable names for partial segments
				];
				
				// Compile segment based on its type
				switch ($type) {
					case 'variable':
						// Handle variable segments like {id}, {slug}, {id:int}, {path:**}
						$compiledSegment['variable_name'] = $this->segmentAnalyzer->extractVariableName($segment);
						
						// Check if variable has a type constraint (e.g., {id:int})
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
							// Store the compiled regex and variable names
							$compiledSegment['compiled_regex'] = $result[0];    // Regex pattern
							$compiledSegment['variable_names'] = $result[1];    // Array of variable names
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
		 * @param string $segment The route segment to compile
		 * @return array|null Returns [$pattern, $variableNames] or null on failure
		 */
		public function compilePartialSegmentPattern(string $segment): ?array {
			// Initialize position tracker for character-by-character parsing
			$position = 0;
			
			// Build the regex pattern as we process the segment
			$pattern = '';
			
			// Track variable names found in the segment for later reference
			$variableNames = [];
			
			// Cache segment length to avoid repeated strlen() calls
			$segmentLength = strlen($segment);
			
			// Process each character in the segment
			while ($position < $segmentLength) {
				// Check if we've found the start of a variable definition
				if ($segment[$position] === '{') {
					// Extract the complete variable content between { and }
					$variableContent = $this->extractVariableContent($segment, $position);
					
					// If variable extraction failed (malformed syntax), return null
					if ($variableContent === null) {
						return null;
					}
					
					// Parse the variable definition to get name and regex pattern
					$variableInfo = $this->parseVariableDefinition($variableContent);
					
					// Store the variable name for the return array
					$variableNames[] = $variableInfo['name'];
					
					// Add a named capture group to the regex pattern
					// Format: (?<name>regex) where name is escaped for regex safety
					$pattern .= '(?<' . preg_quote($variableInfo['name'], '/') . '>' . $variableInfo['regex'] . ')';
					
					// Note: $position is advanced by extractVariableContent()
				} else {
					// For literal characters, escape them for regex and add to pattern
					$pattern .= preg_quote($segment[$position], '/');
					
					// Move to the next character
					$position++;
				}
			}
			
			// Return the complete regex pattern with anchors and the variable names
			// ^...$ ensures the pattern matches the entire string
			// /u flag enables Unicode support
			return ['/^' . $pattern . '$/u', $variableNames];
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
			$segments = explode('/', ltrim($routePath, '/'));
			
			return array_filter($segments, function ($segment) {
				return $segment !== '';
			});
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
				if ($segment[$position] === '{') {
					$braceDepth++;
				}
				// Check for closing brace - decreases nesting depth
				elseif ($segment[$position] === '}') {
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
			// Check if the variable has a type specification (contains ':')
			// Examples: 'id' (no type) vs 'id:int' (with type)
			if (!str_contains($content, ':')) {
				// No type specified - use default regex that matches any non-slash characters
				// This prevents variables from matching across URL segments
				return [
					'name'  => $content,
					'regex' => '[^\/]+'  // Match one or more non-slash characters
				];
			}
			
			// Split on first colon to separate name from type definition
			// Limit to 2 parts in case the regex itself contains colons
			$parts = explode(':', $content, 2);
			
			// Return the variable name and resolve the type to its regex pattern
			return [
				'name'  => $parts[0],                              // Variable name (before colon)
				'regex' => $this->resolveTypeToRegex($parts[1])    // Type converted to regex pattern
			];
		}
	}