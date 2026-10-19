<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	/**
	 * Atomic admission storage for rate limiting.
	 *
	 * Each method performs one complete admission decision - read, decide, write -
	 * as a single atomic operation against the backing store, so the count, the
	 * admit/reject decision, and the persisted state can never be observed or left
	 * inconsistent between concurrent callers.
	 *
	 * Timestamp precision: whole Unix seconds. $now is supplied by the caller (rather
	 * than each implementation calling time() itself) so strategy tests can use a
	 * controllable clock.
	 *
	 * Expiration: implementations are responsible for expiring their own per-key state
	 * (e.g. a fixed window's counter, a sliding window's timestamp set, a bucket's
	 * token/refill state) once it can no longer affect a future decision for that key.
	 *
	 * Unavailability: an implementation MUST throw RateLimitStoreUnavailableException
	 * when it cannot complete the atomic operation (backend unreachable, lock not
	 * acquired, retries exhausted, ...). It must never fall back to a fabricated
	 * "not exceeded" result or reset a counter it couldn't actually read - callers
	 * decide what an outage means for the request (RateLimitAspect fails closed by
	 * default, with an explicit opt-in to fail open).
	 */
	interface RateLimitStoreInterface {

		/**
		 * Atomically increment the fixed-window counter for $key and report admission.
		 *
		 * The window is determined by the caller-agnostic boundary floor(now / window) * window,
		 * so all callers within the same window agree on its identity without coordination.
		 *
		 * @param string $key Rate limit key (scope + identifier + route, already sanitized)
		 * @param int $limit Maximum requests admitted per window
		 * @param int $window Window length in seconds
		 * @param int $now Current Unix timestamp (seconds)
		 * @return RateLimitResult
		 * @throws \Quellabs\Canvas\Exceptions\RateLimitStoreUnavailableException
		 */
		public function incrementFixedWindow(string $key, int $limit, int $window, int $now): RateLimitResult;

		/**
		 * Atomically record this request in the rolling window for $key and report admission.
		 * @param string $key Rate limit key (scope + identifier + route, already sanitized)
		 * @param int $limit Maximum requests admitted per rolling window
		 * @param int $window Window length in seconds
		 * @param int $now Current Unix timestamp (seconds)
		 * @return RateLimitResult
		 * @throws \Quellabs\Canvas\Exceptions\RateLimitStoreUnavailableException
		 */
		public function admitSlidingWindow(string $key, int $limit, int $window, int $now): RateLimitResult;

		/**
		 * Atomically refill and, if available, consume one token from the bucket for $key.
		 * @param string $key Rate limit key (scope + identifier + route, already sanitized)
		 * @param int $limit Bucket capacity (also the refill target over $window seconds)
		 * @param int $window Seconds to fully refill an empty bucket to $limit tokens
		 * @param int $now Current Unix timestamp (seconds)
		 * @return RateLimitResult
		 * @throws \Quellabs\Canvas\Exceptions\RateLimitStoreUnavailableException
		 */
		public function admitTokenBucket(string $key, int $limit, int $window, int $now): RateLimitResult;
	}
