<?php

	namespace Quellabs\Canvas\Error;

	/**
	 * An exception that carries headers for the response DefaultErrorHandler builds
	 * for it. The generic extension point RateLimitException and MethodNotAllowedException
	 * use instead of DefaultErrorHandler knowing their concrete classes - any other
	 * exception (e.g. a custom rate limiter's own exception) gets the same treatment
	 * just by implementing this.
	 */
	interface ProvidesResponseHeaders {

		/**
		 * Headers to apply to the response this exception produces
		 * @return array<string, string|int>
		 */
		public function getHeaders(): array;
	}
