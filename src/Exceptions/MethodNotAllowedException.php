<?php

	namespace Quellabs\Canvas\Exceptions;

	use Throwable;

	/**
	 * Exception thrown when a request path matches a route but the HTTP method does not.
	 *
	 * Distinguishing this from RouteNotFoundException lets the kernel return a 405
	 * (with an Allow header listing the methods that path actually supports) instead
	 * of masking the mismatch as a plain 404.
	 */
	class MethodNotAllowedException extends HttpException {

		/** @var list<string> HTTP methods the matched path actually supports */
		private array $allowedMethods;

		/**
		 * Create a new method-not-allowed exception instance.
		 * @param list<string> $allowedMethods HTTP methods the matched path actually supports.
		 * @param string $message Exception message.
		 * @param int $code HTTP status code (405).
		 * @param Throwable|null $previous Previous exception instance.
		 */
		public function __construct(
			array      $allowedMethods,
			string     $message = 'Method not allowed',
			int        $code = 405,
			?Throwable $previous = null
		) {
			parent::__construct($message, $code, $previous);
			$this->allowedMethods = $allowedMethods;
		}

		/**
		 * Get the HTTP methods that the matched path actually supports.
		 * @return list<string>
		 */
		public function getAllowedMethods(): array {
			return $this->allowedMethods;
		}
	}
