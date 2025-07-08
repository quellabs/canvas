<?php
	
	namespace Quellabs\Canvas\Legacy\Resolvers;
	
	use Quellabs\Canvas\Legacy\FileResolverInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * This resolver handles WordPress-style permalinks with date-based URLs
	 * in the format /YYYY/MM/post-slug and maps them to corresponding PHP files.
	 * This is useful for maintaining backward compatibility with WordPress-style URLs.
	 */
	class WordPressStyleResolver implements FileResolverInterface {
		
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
			$this->legacyPath = $legacyPath;
		}
		
		/**
		 * Resolve WordPress-style blog post URLs to legacy PHP files
		 *
		 * This method specifically handles date-based permalink structures commonly
		 * used by WordPress blogs. It parses URLs in the format /YYYY/MM/post-slug
		 * and attempts to locate corresponding PHP files.
		 *
		 * URL Pattern: /2024/03/my-blog-post
		 * Maps to file: posts/2024-03-my-blog-post.php
		 *
		 * @param string $path The request path to resolve (e.g., "/2024/03/my-blog-post")
		 * @param Request $request The HTTP request object (currently unused but available for future extensions)
		 * @return string|null The absolute file path if found, null if URL doesn't match pattern or file doesn't exist
		 */
		public function resolve(string $path, Request $request): ?string {
			// Handle WordPress-style permalink URLs: /YYYY/MM/post-slug
			// Regex breakdown:
			// ^/          - Must start with forward slash
			// (\d{4})     - Capture exactly 4 digits (year)
			// /           - Literal forward slash
			// (\d{2})     - Capture exactly 2 digits (month)
			// /           - Literal forward slash
			// ([^/]+)     - Capture one or more non-slash characters (post slug)
			if (preg_match('#^/(\d{4})/(\d{2})/([^/]+)#', $path, $matches)) {
				$year = $matches[1];   // Extract year (e.g., "2024")
				$month = $matches[2];  // Extract month (e.g., "03")
				$slug = $matches[3];   // Extract post slug (e.g., "my-blog-post")
				
				// Construct file path: posts/YYYY-MM-slug.php
				$file = $this->legacyPath . "posts/{$year}-{$month}-{$slug}.php";
				
				// Return file path if it exists, null otherwise
				return file_exists($file) ? $file : null;
			}
			
			// URL doesn't match WordPress-style pattern
			return null;
		}
	}