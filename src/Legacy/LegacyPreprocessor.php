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
			
			// Validate that that worked
			if ($content === false) {
				throw new \RuntimeException("Failed to read file: {$filePath}");
			}
			
			// Apply transformations in sequence
			// Replace exit() calls with return statements for Canvas compatibility
			$content = $this->replaceExitCalls($content);
			
			// Replace header() calls with Canvas-compatible header collection
			$content = $this->replaceHeaderCalls($content);
			
			// Replace http_response_code() calls with Canvas header collection function
			$content = $this->replaceHttpResponseCodeCalls($content);
			
			// Replace mysqli_query() calls with monitored version
			$content = $this->replaceMysqliQueryCalls($content);
			$content = $this->replaceMysqliPrepareCalls($content);
			
			// Replace PDO instantiation
			$content = $this->replacePdoInstantiation($content);
			
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
			
			// Replace the given statements for their Canvas counterparts
			$result = preg_replace(array_keys($patterns), array_values($patterns), $content);
			
			// A null result means PCRE failed - any surviving exit()/die() calls would
			// terminate the PHP process directly, killing the Canvas request lifecycle
			if ($result === null) {
				throw new \RuntimeException("Failed to replace exit/die calls in preprocessed content");
			}
			
			// Return the replaced result
			return $result;
		}
		
		/**
		 * Replace header() calls with Canvas header collection function.
		 * @param string $content The PHP content to process
		 * @return string Content with header() calls replaced
		 */
		private function replaceHeaderCalls(string $content): string {
			// Match header() calls with string literals and optional parameters
			$pattern = '/header\s*\(\s*([\'"])([^\1]*?)\1\s*(?:,\s*(true|false))?\s*(?:,\s*(\d+))?\s*\)/';
			
			$result = preg_replace_callback($pattern, function ($matches) {
				$headerValue = $matches[2];
				
				// Default replace to true if not explicitly specified (mirrors PHP's own default)
				$replace = $matches[3] ?? 'true';
				$responseCode = $matches[4] ?? null;
				
				// Escape single quotes in the header value to keep the generated code valid
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
			
			// A null result means PCRE failed - raw header() calls would send headers
			// directly, bypassing Canvas's response lifecycle
			if ($result === null) {
				throw new \RuntimeException("Failed to replace header() calls in preprocessed content");
			}
			
			return $result;
		}
		
		/**
		 * Replace http_response_code() calls with Canvas header collection function.
		 * @param string $content The PHP content to process
		 * @return string Content with http_response_code() calls replaced
		 */
		private function replaceHttpResponseCodeCalls(string $content): string {
			// Match http_response_code() calls with a numeric status code argument
			// Captures the status code in group 1: http_response_code(404)
			$pattern = '/http_response_code\s*\(\s*(\d+)\s*\)/';
			
			$result = preg_replace_callback($pattern, function ($matches) {
				// Cast to int to strip any leading zeros from the matched digits
				$statusCode = (int)$matches[1];
				
				// Rewrite as a canvas_header() Status line - this routes the response
				// code through Canvas's header collection instead of sending it directly,
				// which would bypass the framework's response lifecycle
				return "canvas_header('Status: {$statusCode}', true)";
			}, $content);
			
			// A null result means PCRE failed entirely - the file would retain the raw
			// http_response_code() call and send headers outside Canvas's control
			if ($result === null) {
				throw new \RuntimeException("Failed to replace http_response_code() calls in preprocessed content");
			}
			
			return $result;
		}
		
		/**
		 * Replace mysqli_query() calls with the monitored version for inspection.
		 * This allows automatic monitoring of all database queries in the inspector.
		 * @param string $content The PHP content to process
		 * @return string Content with mysqli_query() calls replaced
		 */
		private function replaceMysqliQueryCalls(string $content): string {
			// Pattern to match mysqli_query calls with various parameter combinations
			// mysqli_query($connection, $query) or mysqli_query($connection, $query, $resultmode)
			$pattern = '/\bmysqli_query\s*\(\s*([^,]+),\s*([^,)]+)(?:\s*,\s*([^)]+))?\s*\)/';
			
			$result = preg_replace_callback($pattern, function ($matches) {
				$connection = trim($matches[1]);
				$query = trim($matches[2]);
				
				// Optional third argument - preserve it if present
				$resultMode = isset($matches[3]) ? ', ' . trim($matches[3]) : '';
				
				// Wrap with the monitored version so Canvas can intercept and log the query
				return "canvas_mysqli_query({$connection}, {$query}{$resultMode})";
			}, $content);
			
			// A null result means PCRE failed - the raw mysqli_query() would execute
			// unmonitored, bypassing the inspector entirely
			if ($result === null) {
				throw new \RuntimeException("Failed to replace mysqli_query() calls in preprocessed content");
			}
			
			return $result;
		}
		
		/**
		 * Replace mysqli_prepare() calls with monitored version.
		 * @param string $content The PHP content to process
		 * @return string Content with mysqli_prepare() calls replaced
		 */
		private function replaceMysqliPrepareCalls(string $content): string {
			// Pattern to match mysqli_prepare calls
			$pattern = '/\bmysqli_prepare\s*\(\s*([^,]+),\s*([^)]+)\s*\)/';
			
			// Perform the regexp rereplacement
			$result = preg_replace_callback($pattern, function ($matches) {
				$connection = trim($matches[1]);
				$query = trim($matches[2]);
				
				// Wrap with the monitored version so Canvas can intercept prepared statements
				return "canvas_mysqli_prepare({$connection}, {$query})";
			}, $content);
			
			// A null result means PCRE failed - the raw mysqli_prepare() would execute
			// unmonitored, bypassing the inspector entirely
			if ($result === null) {
				throw new \RuntimeException("Failed to replace mysqli_prepare() calls in preprocessed content");
			}
			
			return $result;
		}
		
		/**
		 * Replace new PDO() instantiation with canvas_create_pdo()
		 * This allows wrapping the PDO instance for automatic query monitoring
		 * @param string $content The PHP content to process
		 * @return string Content with PDO instantiation replaced
		 */
		private function replacePdoInstantiation(string $content): string {
			// Match: new PDO(...)
			// This pattern handles:
			// - new PDO(...)
			// - new \PDO(...)
			// - new \Namespace\PDO(...) - won't match, which is correct
			$pattern = '/\bnew\s+\\\\?PDO\s*\(/';
			
			// Replace the content
			$result = preg_replace($pattern, 'canvas_create_pdo(', $content);
			
			// A null result means PCRE failed - raw PDO instantiation would create an
			// unwrapped connection that Canvas cannot monitor for query inspection
			if ($result === null) {
				throw new \RuntimeException("Failed to replace PDO instantiation in preprocessed content");
			}
			
			// Return the replaced result
			return $result;
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
			$usePattern = '/\buse\s+[^;{]+(?:\{[^}]*})?[^;]*;/i';
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