<?php
	
	namespace Quellabs\Canvas\Legacy;
	
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Interface for legacy file resolvers.
	 *
	 * This interface defines the contract for classes that resolve incoming HTTP request
	 * paths to legacy PHP files. Different implementations can handle various URL patterns
	 * and file organization schemes (e.g., WordPress-style permalinks, flat file structure, etc.).
	 */
	interface FileResolverInterface {
		
		/**
		 * Resolve a request path to a legacy file path
		 *
		 * This method attempts to map an incoming HTTP request path to a physical
		 * legacy PHP file that should handle the request. The implementation should
		 * return the absolute file path if a matching file is found, or null if
		 * this particular resolver cannot handle the given path.
		 *
		 * @param string $path The URL path from the HTTP request (e.g., "/users", "/2024/03/my-post")
		 * @param Request $request The complete HTTP request object, providing access to headers,
		 *                        query parameters, method, and other request data that may
		 *                        influence file resolution
		 * @return string|null The absolute file system path to the legacy PHP file if found,
		 *                    or null if this resolver cannot handle the path or no matching file exists
		 *
		 * @example
		 * // Example usage:
		 * $resolver = new SomeFileResolver('/path/to/legacy/');
		 * $filePath = $resolver->resolve('/users/profile', $request);
		 * // Returns: '/path/to/legacy/users/profile.php' or null
		 */
		public function resolve(string $path, Request $request): ?string;
	}