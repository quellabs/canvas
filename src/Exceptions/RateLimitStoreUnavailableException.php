<?php

	namespace Quellabs\Canvas\Exceptions;

	use Throwable;

	/**
	 * Thrown by a RateLimitStoreInterface implementation when it cannot complete
	 * an atomic admission operation (backend unreachable, lock not acquired,
	 * retries exhausted, ...).
	 *
	 * Implementations must throw this rather than silently returning a fabricated
	 * "not exceeded" result or resetting the counter - RateLimitAspect is the only
	 * place that decides what a storage outage means for the request (fail closed
	 * by default, or fail open when explicitly configured via onStoreFailure).
	 *
	 * Extends HttpException so an outage that isn't caught anywhere still resolves
	 * to a 503 through the normal exception-handling path, rather than a 500.
	 */
	class RateLimitStoreUnavailableException extends HttpException {

		/**
		 * @param string $message Human-readable description of the storage failure
		 * @param int $code HTTP status code (503 by default)
		 * @param Throwable|null $previous The underlying storage/connection failure, if any
		 */
		public function __construct(
			string     $message = 'Rate limit storage is unavailable',
			int        $code = 503,
			?Throwable $previous = null
		) {
			parent::__construct($message, $code, $previous);
		}
	}
