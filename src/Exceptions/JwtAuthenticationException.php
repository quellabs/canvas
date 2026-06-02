<?php
	
	namespace Quellabs\Canvas\Exceptions;
	
	use Throwable;
	
	/**
	 * Thrown when JWT validation fails and throwOnFailure is enabled.
	 *
	 * The HTTP status code is always 401. The message contains the specific
	 * reason (expired, bad signature, etc.) and is safe to surface to clients.
	 *
	 * To produce a proper JSON response, register an ErrorHandlerInterface
	 * that handles this exception type. The default Canvas error handler
	 * returns HTML.
	 */
	class JwtAuthenticationException extends HttpException {
		
		/**
		 * JwtAuthenticationException constructor
		 * @param string $message Reason for the authentication failure
		 * @param Throwable|null $previous Previous exception for chaining
		 */
		public function __construct(string $message = 'Unauthorized', ?Throwable $previous = null) {
			parent::__construct($message, 401, $previous);
		}
	}