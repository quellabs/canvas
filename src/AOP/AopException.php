<?php
	
	namespace Quellabs\Canvas\AOP;
	
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Custom exception class that carries a Symfony Response object.
	 *
	 * This exception is designed for AOP (Aspect-Oriented Programming) scenarios
	 * where you need to interrupt normal execution flow and return a specific
	 * HTTP response. Useful for middleware, interceptors, or when you need to
	 * short-circuit application logic with a custom response.
	 */
	class AopException extends \Exception {

		/**
		 * @var Response The Symfony Response object to be returned
		 */
		private Response $response;
		
		/**
		 * Constructor for AopException
		 * @param Response $response The Symfony Response object that should be returned when this exception is caught
		 * @param string $message Optional exception message for debugging/logging purposes
		 * @param int $code Optional exception code (defaults to 0)
		 * @param \Throwable|null $previous Optional previous exception for exception chaining
		 */
		public function __construct(Response $response, string $message = '', int $code = 0, \Throwable $previous = null) {
			// Store the response object for later retrieval
			$this->response = $response;
			
			// Call parent constructor to initialize base Exception properties
			parent::__construct($message, $code, $previous);
		}
		
		/**
		 * Get the Symfony Response object associated with this exception
		 * @return Response The response object that should be returned to the client
		 */
		public function getResponse(): Response {
			return $this->response;
		}
	}