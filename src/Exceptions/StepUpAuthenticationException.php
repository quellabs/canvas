<?php

	namespace Quellabs\Canvas\Exceptions;

	use Throwable;

	/**
	 * Thrown when a request is authenticated but not recently — or not strongly —
	 * enough for the requested action, and throwOnFailure is enabled on
	 * StepUpAuthenticationAspect.
	 *
	 * Distinct from JwtAuthenticationException (401, not authenticated at all):
	 * this is a 403 — the credential is valid, it's just too old or too weak
	 * for a sensitive action.
	 *
	 * Carries enough context (required window, required methods, the methods
	 * actually presented, and the original request's method/path) for a
	 * centralized handler to build a machine-readable "step-up required"
	 * response — the client re-authenticates against this information and
	 * simply retries the same request with a fresh credential.
	 */
	class StepUpAuthenticationException extends HttpException {

		/**
		 * Required freshness window in seconds
		 * @var int
		 */
		private readonly int $maxAge;

		/**
		 * Authentication methods that would satisfy this check, if restricted
		 * @var string[]
		 */
		private readonly array $requiredMethods;

		/**
		 * Authentication methods actually present on the request's token
		 * @var string[]
		 */
		private readonly array $presentedMethods;

		/**
		 * HTTP method of the request that was denied
		 * @var string
		 */
		private readonly string $requestMethod;

		/**
		 * Path of the request that was denied
		 * @var string
		 */
		private readonly string $requestPath;

		/**
		 * StepUpAuthenticationException constructor
		 * @param int $maxAge Required freshness window in seconds
		 * @param string[] $requiredMethods Authentication methods that would satisfy this check, if restricted
		 * @param string[] $presentedMethods Authentication methods actually present on the request's token
		 * @param string $requestMethod HTTP method of the request that was denied
		 * @param string $requestPath Path of the request that was denied
		 * @param Throwable|null $previous Previous exception for chaining
		 */
		public function __construct(
			int $maxAge,
			array $requiredMethods,
			array $presentedMethods,
			string $requestMethod,
			string $requestPath,
			?Throwable $previous = null
		) {
			parent::__construct("Re-authentication required within the last {$maxAge} seconds", 403, $previous);

			$this->maxAge = $maxAge;
			$this->requiredMethods = $requiredMethods;
			$this->presentedMethods = $presentedMethods;
			$this->requestMethod = $requestMethod;
			$this->requestPath = $requestPath;
		}

		/**
		 * Get the freshness window that was required.
		 * @return int Required max age in seconds
		 */
		public function getMaxAge(): int {
			return $this->maxAge;
		}

		/**
		 * Get the authentication methods that would satisfy this check.
		 * @return string[] Required methods, or an empty array when the check is recency-only
		 */
		public function getRequiredMethods(): array {
			return $this->requiredMethods;
		}

		/**
		 * Get the authentication methods actually presented on the denied request.
		 * @return string[] Methods from the token's auth_methods, or an empty array when none were present
		 */
		public function getPresentedMethods(): array {
			return $this->presentedMethods;
		}

		/**
		 * Get the HTTP method of the request that was denied, so a client can retry it after stepping up.
		 * @return string HTTP method
		 */
		public function getRequestMethod(): string {
			return $this->requestMethod;
		}

		/**
		 * Get the path of the request that was denied, so a client can retry it after stepping up.
		 * @return string Request path
		 */
		public function getRequestPath(): string {
			return $this->requestPath;
		}
	}
