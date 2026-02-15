<?php
	
	namespace Quellabs\Canvas\Error;
	
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Contract for framework-level error handlers.
	 */
	interface ErrorHandlerInterface {
		
		/**
		 * Determine whether this handler supports the given exception.
		 * @param \Throwable $exception The thrown exception.
		 * @return bool True if this handler can handle the exception, false otherwise.
		 */
		public function supports(\Throwable $exception): bool;
		
		/**
		 * Convert the given exception into an HTTP response.
		 *
		 * This method is invoked only if supports() returns true.
		 * Implementations are responsible for:
		 * - Generating the appropriate response content
		 * - Setting the correct HTTP status code
		 * - Returning a fully constructed Response instance
		 *
		 * @param \Throwable $exception The thrown exception being handled.
		 * @param Request $request The current HTTP request.
		 * @return Response The HTTP response representing the error.
		 */
		public function handle(\Throwable $exception, Request $request): Response;
	}
