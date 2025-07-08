<?php
	
	namespace Quellabs\Canvas\Exceptions;
	
	/**
	 * Exception thrown when a requested route cannot be found
	 *
	 * This exception is used throughout the Canvas framework to indicate
	 * that neither Canvas routes nor legacy files can handle a request.
	 * It provides detailed information about the failed request for debugging.
	 */
	class RouteNotFoundException extends \Exception {
		
		/**
		 * The requested path that could not be found
		 * @var string|null
		 */
		private ?string $requestedPath;
		
		/**
		 * The HTTP method used for the request
		 * @var string|null
		 */
		private ?string $requestedMethod;
		
		/**
		 * RouteNotFoundException constructor
		 * @param string $message Exception message describing what wasn't found
		 * @param int $code HTTP status code (defaults to 404)
		 * @param \Throwable|null $previous Previous exception for exception chaining
		 * @param string|null $path The requested path that failed
		 * @param string|null $method The HTTP method that was used
		 */
		public function __construct(
			string     $message = 'Route not found',
			int        $code = 404,
			\Throwable $previous = null,
			string     $path = null,
			string     $method = null
		) {
			parent::__construct($message, $code, $previous);
			$this->requestedPath = $path;
			$this->requestedMethod = $method;
		}
		
		/**
		 * Create exception for a specific request that failed Canvas routing
		 *
		 * Use this when Canvas route resolution fails and you want to provide
		 * specific details about what was requested.
		 * @param string $path The requested URL path
		 * @param string $method The HTTP method (GET, POST, etc.)
		 * @return RouteNotFoundException
		 */
		public static function forRequest(string $path, string $method = 'GET'): RouteNotFoundException {
			return new self(
				"No route found for {$method} {$path}",
				404,
				null,
				$path,
				$method
			);
		}
		
		/**
		 * Create exception for legacy fallthrough failure
		 *
		 * Use this when both Canvas routing and legacy file resolution fail.
		 * This indicates that neither modern routes nor legacy files could
		 * handle the request.
		 * @param string $path The requested URL path
		 * @return RouteNotFoundException
		 */
		public static function forLegacyFallthrough(string $path): RouteNotFoundException {
			return new self(
				"No Canvas route or legacy file found for {$path}",
				404,
				null,
				$path
			);
		}
		
		/**
		 * Get the requested path that couldn't be found
		 * @return string|null The URL path that was requested or null if not set
		 */
		public function getRequestedPath(): ?string {
			return $this->requestedPath;
		}
		
		/**
		 * Get the requested HTTP method
		 * @return string|null The HTTP method that was used, or null if not set
		 */
		public function getRequestedMethod(): ?string {
			return $this->requestedMethod;
		}
		
		/**
		 * Check if this exception has request details
		 * @return bool True if the request path is available, false otherwise
		 */
		public function hasRequestDetails(): bool {
			return $this->requestedPath !== null;
		}
	}