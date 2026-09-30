<?php

	namespace Quellabs\Canvas\Exceptions;

	use Throwable;

	/**
	 * Thrown when session validation fails and throwOnFailure is enabled.
	 *
	 * The HTTP status code is always 401. To produce a proper JSON response,
	 * register an ErrorHandlerInterface that handles this exception type; the
	 * default Canvas error handler returns HTML.
	 */
	class SessionAuthenticationException extends HttpException {

		/**
		 * SessionAuthenticationException constructor
		 * @param string $message Reason for the authentication failure
		 * @param Throwable|null $previous Previous exception for chaining
		 */
		public function __construct(string $message = 'Unauthorized', ?Throwable $previous = null) {
			parent::__construct($message, 401, $previous);
		}
	}
