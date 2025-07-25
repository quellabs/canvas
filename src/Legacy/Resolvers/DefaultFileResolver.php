<?php
	
	namespace Quellabs\Canvas\Legacy\Resolvers;
	
	use Quellabs\Canvas\Legacy\FileResolverInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * This resolver attempts to locate legacy PHP files using common naming conventions.
	 * It tries multiple file path patterns to find the appropriate legacy file to execute.
	 */
	class DefaultFileResolver implements FileResolverInterface {
		
		/**
		 * Base path to the legacy files directory
		 * @var string
		 */
		private string $legacyPath;
		
		/**
		 * DefaultFileResolver constructor
		 * @param string $legacyPath The base directory path where legacy files are stored
		 */
		public function __construct(string $legacyPath) {
			// Remove trailing directory separator to ensure consistent path handling
			$this->legacyPath = rtrim($legacyPath, DIRECTORY_SEPARATOR);
		}
		
		/**
		 * Resolve a request path to a legacy PHP file
		 *
		 * This method attempts to find a matching legacy PHP file for the given path
		 * by trying common file naming patterns. It normalizes the input path and
		 * checks for files in the following order:
		 * 1. Direct file match: path.php
		 * 2. Index file in directory: path/index.php
		 *
		 * @param string $path The request path to resolve (e.g., "/users", "/admin/dashboard")
		 * @param Request $request The HTTP request object (currently unused but available for future extensions)
		 * @return string|null The absolute file path if found, null if no matching file exists
		 */
		public function resolve(string $path, Request $request): ?string {
			// Normalize the path by removing leading/trailing slashes
			$path = trim($path, '/');
			
			// Check if the path already ends with .php extension
			if (str_ends_with($path, ".php")) {
				// Handle direct PHP file requests (e.g., "script.php")
				return $this->resolveDirectPhpFile($path);
			}
			
			// Handle paths without .php extension (e.g., "users", "admin/dashboard")
			return $this->resolvePath($path);
		}
		
		/**
		 * Resolve a path to a legacy PHP file using common naming patterns
		 *
		 * Attempts to find files in the following order:
		 * 1. Direct file: /users -> legacy/users.php
		 * 2. Index file in directory: /users -> legacy/users/index.php
		 *
		 * @param string $path The normalized path without .php extension
		 * @return string|null The absolute file path if found, null otherwise
		 */
		private function resolvePath(string $path): ?string {
			// Build array of potential file locations to check
			$candidates = [
				// Try direct file match: path.php
				$this->legacyPath . DIRECTORY_SEPARATOR . $path . '.php',
				// Try index file in directory: path/index.php
				$this->legacyPath . DIRECTORY_SEPARATOR . $path . DIRECTORY_SEPARATOR . 'index.php',
			];
			
			// Check each candidate file path in order of preference
			foreach ($candidates as $file) {
				if (file_exists($file) && is_readable($file)) {
					// Return the first matching file found
					return $file;
				}
			}
			
			// No matching file found after trying all patterns
			return null;
		}
		
		/**
		 * Handles requests that already include the .php extension
		 * (e.g., "admin/script.php" -> "legacy/admin/script.php")
		 * @param string $path The path that already ends with .php
		 * @return string|null The absolute file path if it exists, null otherwise
		 */
		private function resolveDirectPhpFile(string $path): ?string {
			// Construct the full file path by combining legacy base path with the PHP file path
			$candidate = $this->legacyPath . DIRECTORY_SEPARATOR . $path;
			
			// Check if the file actually exists on the filesystem
			if (file_exists($candidate) && is_readable($candidate)) {
				// Return the verified file path
				return $candidate;
			}
			
			// File not found
			return null;
		}
	}