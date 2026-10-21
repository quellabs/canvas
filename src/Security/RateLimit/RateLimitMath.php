<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	/**
	 * Pure, backend-agnostic admission math shared by store implementations that
	 * perform their own read-modify-write locking in PHP (FileRateLimitStore,
	 * MemcachedRateLimitStore's CAS loop). RedisRateLimitStore computes the
	 * equivalent logic server-side in Lua instead, since Redis's single-threaded
	 * execution model doesn't need a PHP-side critical section at all.
	 *
	 * Every method takes the previously persisted state (null when there was
	 * none) and returns the state to persist next, paired with the admission
	 * result for this request. The caller is responsible for making that pair
	 * durable atomically (holding a lock across both, or a CAS write of the
	 * new state) - this class has no side effects and performs no I/O.
	 */
	final class RateLimitMath {

		/** @var int Floor on how many fixed-window/sliding-window multiples to retain state for */
		private const int MIN_TRACKED_TIMESTAMPS = 100;

		/**
		 * Static-only: pure functions, no instance state.
		 */
		private function __construct() {
		}

		/**
		 * Fixed window: the window boundary is floor(now / window) * window, so every
		 * caller within the same window computes the same boundary without coordination.
		 * @param array<string, mixed>|null $state Previously persisted state for this window, or null
		 * @param int $limit Maximum requests admitted per window
		 * @param int $window Window length in seconds
		 * @param int $now Current Unix timestamp (seconds)
		 * @return RateLimitAdmission
		 */
		public static function fixedWindow(?array $state, int $limit, int $window, int $now): RateLimitAdmission {
			$windowStart = intdiv($now, $window) * $window;
			$resetTime = $windowStart + $window;

			$count = (is_int($state['count'] ?? null) ? $state['count'] : 0) + 1;

			$result = new RateLimitResult(
				$count,
				$count > $limit,
				$resetTime,
				max(0, $resetTime - $now)
			);

			return new RateLimitAdmission(['count' => $count], $result);
		}

		/**
		 * Sliding window: tracks individual request timestamps so the window rolls
		 * continuously rather than resetting at fixed boundaries. Caps how many
		 * timestamps are retained so sustained abuse can't grow state unboundedly -
		 * once well past the limit, the exact count no longer changes the decision.
		 * @param array<string, mixed>|null $state Previously persisted timestamps for this key, or null
		 * @param int $limit Maximum requests admitted per rolling window
		 * @param int $window Window length in seconds
		 * @param int $now Current Unix timestamp (seconds)
		 * @return RateLimitAdmission
		 */
		public static function slidingWindow(?array $state, int $limit, int $window, int $now): RateLimitAdmission {
			$cutoff = $now - $window;

			$timestamps = is_array($state['timestamps'] ?? null) ? $state['timestamps'] : [];
			$timestamps = array_values(array_filter(
				$timestamps,
				static fn($ts) => is_int($ts) && $ts > $cutoff
			));

			// Bound memory under sustained abuse: once far past the limit, trimming the
			// oldest excess only makes retry_after's "oldest" estimate more conservative
			// (longer), never incorrectly permissive.
			$maxTracked = max($limit * 4, self::MIN_TRACKED_TIMESTAMPS);

			if (count($timestamps) > $maxTracked) {
				$timestamps = array_slice($timestamps, -$maxTracked);
			}

			$timestamps[] = $now;

			$count = count($timestamps);
			$exceeded = $count > $limit;

			// retry_after must wait for enough of the *oldest* entries to expire that
			// admitting one more request would no longer exceed $limit - not just for
			// the single oldest entry, which can still leave the window full.
			if ($exceeded && is_int($timestamps[$count - $limit] ?? null)) {
				$expiringTimestamp = $timestamps[$count - $limit];
			} else {
				$expiringTimestamp = $now;
			}

			$result = new RateLimitResult(
				$count,
				$exceeded,
				$now + $window,
				$exceeded ? max(0, ($expiringTimestamp + $window) - $now) : 0
			);

			return new RateLimitAdmission(['timestamps' => $timestamps], $result);
		}

		/**
		 * Token bucket: refills continuously at limit/window tokens per second, up to
		 * $limit tokens, and consumes one token per admitted request.
		 * @param array<string, mixed>|null $state Previously persisted bucket state, or null
		 * @param int $limit Bucket capacity (also the refill target over $window seconds)
		 * @param int $window Seconds to fully refill an empty bucket to $limit tokens
		 * @param int $now Current Unix timestamp (seconds)
		 * @return RateLimitAdmission
		 */
		public static function tokenBucket(?array $state, int $limit, int $window, int $now): RateLimitAdmission {
			$refillRate = $window > 0 ? $limit / $window : (float)$limit;

			if (is_numeric($state['tokens'] ?? null) && is_int($state['last_refill'] ?? null)) {
				$tokens = (float)$state['tokens'];
				$lastRefill = $state['last_refill'];
			} else {
				$tokens = (float)$limit;
				$lastRefill = $now;
			}

			$elapsed = max(0, $now - $lastRefill);
			$tokens = min((float)$limit, $tokens + $elapsed * $refillRate);
			$exceeded = $tokens < 1;

			if (!$exceeded) {
				$tokens -= 1;
			}

			$retryAfter = $exceeded && $refillRate > 0 ? (int)ceil((1 - $tokens) / $refillRate) : 0;

			$result = new RateLimitResult(
				(int)($limit - floor($tokens)),
				$exceeded,
				$now + $retryAfter,
				$retryAfter
			);

			return new RateLimitAdmission(['tokens' => $tokens, 'last_refill' => $now], $result);
		}
	}
