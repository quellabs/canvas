<?php
	
	namespace Quellabs\Canvas\Exceptions;
	
	use Throwable;
	
	/**
	 * Exception thrown when a request exceeds the configured rate limit.
	 *
	 * This exception is thrown by the RateLimitAspect when throwOnFailure is enabled
	 * and the current request violates the configured rate limiting policy.
	 *
	 * The exception contains detailed metadata about the current rate limiting state,
	 * including retry timing, remaining quota, strategy, and response headers. This
	 * allows centralized exception handlers to generate standards-compliant HTTP 429
	 * responses without recalculating rate limit state.
	 *
	 */
	class RateLimitException extends HttpException {
		
		/**
		 * Create a new rate limit exception instance.
		 *
		 * @param int $limit Maximum number of allowed requests.
		 * @param int $remaining Remaining requests available in the current window.
		 * @param int $retryAfter Number of seconds the client should wait before retrying.
		 * @param int $resetTime Unix timestamp when the rate limit resets.
		 * @param string $strategy The active rate limiting strategy.
		 * @param string $scope The active rate limiting scope.
		 * @param array<string, string|int> $headers HTTP headers associated with the rate limit response.
		 * @param string $message Exception message.
		 * @param int $code HTTP status code (typically 429).
		 * @param Throwable|null $previous Previous exception instance.
		 */
		public function __construct(
			private readonly int $limit,
			private readonly int $remaining,
			private readonly int $retryAfter,
			private readonly int $resetTime,
			private readonly string $strategy,
			private readonly string $scope,
			private readonly array $headers = [],
			string $message = 'Rate limit exceeded',
			int $code = 429,
			?Throwable $previous = null
		) {
			parent::__construct($message, $code, $previous);
		}
		
		/**
		 * Get the configured request limit.
		 * @return int Maximum allowed requests within the configured window.
		 */
		public function getLimit(): int {
			return $this->limit;
		}
		
		/**
		 * Get the remaining number of allowed requests.
		 * @return int Remaining requests available before the limit is exceeded.
		 */
		public function getRemaining(): int {
			return $this->remaining;
		}
		
		/**
		 * Get the retry delay in seconds.
		 * This indicates how long the client should wait before
		 * attempting another request.
		 *
		 * @return int Retry delay in seconds.
		 */
		public function getRetryAfter(): int {
			return $this->retryAfter;
		}
		
		/**
		 * Get the Unix timestamp when the rate limit resets.
		 * @return int Reset timestamp.
		 */
		public function getResetTime(): int {
			return $this->resetTime;
		}
		
		/**
		 * Get the active rate limiting strategy.
		 * @return string Strategy identifier.
		 */
		public function getStrategy(): string {
			return $this->strategy;
		}
		
		/**
		 * Get the active rate limiting scope.
		 * @return string Scope identifier.
		 */
		public function getScope(): string {
			return $this->scope;
		}
		
		/**
		 * Get the HTTP headers associated with this rate limit violation.
		 * @return array<string, string|int> Response headers.
		 */
		public function getHeaders(): array {
			return $this->headers;
		}
	}