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
		 * Constructor
		 * @param string $legacyPath The base directory path where legacy files are stored
		 */
		public function __construct(string $legacyPath) {
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
			
			// Try these patterns in order of preference:
			$candidates = [
				$this->legacyPath .DIRECTORY_SEPARATOR . $path . '.php', // Direct file: /users -> legacy/users.php
				$this->legacyPath . DIRECTORY_SEPARATOR . $path . DIRECTORY_SEPARATOR . 'index.php',  // Index file: /users -> legacy/users/index.php
			];
			
			// Check each candidate file path
			foreach ($candidates as $file) {
				if (file_exists($file)) {
					return $file; // Return the first matching file found
				}
			}
			
			// No matching file found
			return null;
		}
	}