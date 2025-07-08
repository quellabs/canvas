<?php
	
	namespace Quellabs\Canvas\Legacy;
	
	/**
	 * LegacyPreprocessor handles the transformation of legacy PHP code
	 * to make it compatible with the Canvas framework by replacing
	 * problematic function calls and adding helper functions.
	 */
	class LegacyPreprocessor {
		
		/**
		 * Main preprocessing method that transforms legacy PHP code
		 * @param string $filePath Path to the legacy PHP file to process
		 * @return string The processed PHP code as a string
		 */
		public function preprocess(string $filePath): string {
			// Read the original file contents
			$content = file_get_contents($filePath);
			
			// Apply transformations in sequence
			// Replace exit() calls with return statements for Canvas compatibility
			$content = $this->replaceExitCalls($content);
			
			// Replace header() calls with Canvas-compatible header collection
			$content = $this->replaceHeaderCalls($content);
			
			// Replace http_response_code() calls with Canvas header collection function
			$content = $this->replaceHttpResponseCodeCalls($content);
			
			// Inject Canvas helper functions at the appropriate location
			return $this->addCanvasHelper($content);
		}
		
		/**
		 * Replaces various forms of exit() calls with exception throws
		 * This preserves the termination behavior while allowing Canvas to catch and handle it
		 * @param string $content The PHP code to process
		 * @return string The processed code with exit calls replaced
		 */
		private function replaceExitCalls(string $content): string {
			// Define patterns and their replacements for different exit() variations
			$patterns = [
				// exit() with no arguments -> throw exception with code 0
				'/\bexit\s*\(\s*\)/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(0)',
				
				// exit(code) with numeric argument -> throw exception with that code
				'/\bexit\s*\(\s*(\d+)\s*\)/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException($1)',
				
				// exit(message) with string argument -> throw exception with code 1 and message
				'/\bexit\s*\(\s*([\'"][^\'"]*[\'"])\s*\)/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(1, $1)',
				
				// exit; (statement without parentheses) -> throw exception with code 0
				'/\bexit\s*;/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(0);',
				
				// exit (without parentheses or semicolon) -> throw exception with code 0
				'/\bexit\b(?!\s*[\(;])/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(0)',
				
				// die() calls (alias for exit) - same patterns
				'/\bdie\s*\(\s*\)/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(0)',
				'/\bdie\s*\(\s*(\d+)\s*\)/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException($1)',
				'/\bdie\s*\(\s*([\'"][^\'"]*[\'"])\s*\)/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(1, $1)',
				'/\bdie\s*;/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(0);',
				'/\bdie\b(?!\s*[\(;])/' => 'throw new \Quellabs\Canvas\Legacy\LegacyExitException(0)'
			];
			
			return preg_replace(array_keys($patterns), array_values($patterns), $content);
		}
		
		/**
		 * Replace header() calls with Canvas header collection function.
		 * @param string $content The PHP content to process
		 * @return string Content with header() calls replaced
		 */
		private function replaceHeaderCalls(string $content): string {
			// Match header() calls with string literals and optional parameters
			$pattern = '/header\s*\(\s*([\'"])([^\1]*?)\1\s*(?:,\s*(true|false))?\s*(?:,\s*(\d+))?\s*\)/';
			
			return preg_replace_callback($pattern, function ($matches) {
				$headerValue = $matches[2];
				$replace = $matches[3] ?? 'true';
				$responseCode = $matches[4] ?? null;
				
				// Escape single quotes in the header value
				$headerValue = str_replace("'", "\\'", $headerValue);
				
				// Build the canvas_header call
				$call = "canvas_header('{$headerValue}', {$replace}";
				
				// Add response code if provided
				if ($responseCode !== null) {
					$call .= ", {$responseCode}";
				}
				
				$call .= ")";
				
				return $call;
			}, $content);
		}
		
		/**
		 * Replace http_response_code() calls with Canvas header collection function.
		 * @param string $content The PHP content to process
		 * @return string Content with http_response_code() calls replaced
		 */
		private function replaceHttpResponseCodeCalls(string $content): string {
			// Match http_response_code() calls with numeric arguments
			$pattern = '/http_response_code\s*\(\s*(\d+)\s*\)/';
			
			return preg_replace_callback($pattern, function ($matches) {
				$statusCode = (int)$matches[1];
				return "canvas_header('Status: {$statusCode}', true)";
			}, $content);
		}

		/**
		 * Find the best insertion point for Canvas helper code.
		 * This method analyzes the file structure to inject helpers AFTER namespace
		 * declaration and use statements, but before any actual code execution.
		 * @param string $content The PHP file content
		 * @return int The position where helper code should be inserted
		 */
		private function findInsertionPoint(string $content): int {
			$insertPos = 0;
			
			// Find <?php opening tag first
			if (preg_match('/^<\?php\s*/i', $content, $matches, PREG_OFFSET_CAPTURE)) {
				$insertPos = (int)$matches[0][1] + strlen($matches[0][0]);
			}
			
			// Look for namespace declaration AFTER <?php
			if (preg_match('/\bnamespace\s+[^;]+;/i', $content, $matches, PREG_OFFSET_CAPTURE, $insertPos)) {
				$insertPos = (int)$matches[0][1] + strlen($matches[0][0]);
			}
			
			// Find all use statements after the namespace (or after <?php if no namespace)
			$usePattern = '/\buse\s+(?:[^;{]+(?:\{[^}]*\})?[^;]*);/i';
			$searchPos = $insertPos;
			
			// Keep finding use statements and update insertion point to after the last one
			while (preg_match($usePattern, $content, $matches, PREG_OFFSET_CAPTURE, $searchPos)) {
				$insertPos = (int)$matches[0][1] + strlen($matches[0][0]);
				$searchPos = $insertPos;
			}
		
			// Return the insertion point
			return $insertPos;
		}
		
		/**
		 * Add Canvas helper functions at the appropriate location in the PHP file.
		 * This method intelligently finds where to inject the helper code AFTER
		 * namespace declarations and use statements to avoid syntax errors.
		 * @param string $content The original PHP content
		 * @return string Content with Canvas helpers injected at the proper location
		 */
		private function addCanvasHelper(string $content): string {
			// Find the insertion point after namespace and use statements
			$insertPos = $this->findInsertionPoint($content);
			
			// Get the absolute path to the helpers file within the package
			$helpersPath = __DIR__ . '/Helpers/LegacyHelper.php';
			$escapedPath = addslashes($helpersPath); // Escape for PHP string
			
			// Get include require
			$helperInclude = "\n\nrequire_once '{$escapedPath}';\n";
			
			// Insert the helper code at the determined position
			$before = substr($content, 0, $insertPos);
			$after = substr($content, $insertPos);
			
			// Return modified code
			return $before . $helperInclude . $after;
		}
	}