<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	/**
	 * Outcome of a single atomic admission check against a RateLimitStoreInterface.
	 * Immutable value object: one admission operation, one result, no partial state.
	 */
	final class RateLimitResult {

		/** @var int Requests counted against the limit so far (window or bucket-consumption count) */
		private int $count;

		/** @var bool True if this request exceeds the configured limit */
		private bool $exceeded;

		/** @var int Unix timestamp (seconds) when the limit resets */
		private int $resetTime;

		/** @var int Seconds the client should wait before retrying; 0 when not exceeded */
		private int $retryAfter;

		/**
		 * @param int $count Requests counted against the limit so far
		 * @param bool $exceeded True if this request exceeds the configured limit
		 * @param int $resetTime Unix timestamp (seconds) when the limit resets
		 * @param int $retryAfter Seconds the client should wait before retrying
		 */
		public function __construct(int $count, bool $exceeded, int $resetTime, int $retryAfter) {
			$this->count = $count;
			$this->exceeded = $exceeded;
			$this->resetTime = $resetTime;
			$this->retryAfter = $retryAfter;
		}

		/**
		 * @return int Requests counted against the limit so far
		 */
		public function getCount(): int {
			return $this->count;
		}

		/**
		 * @return bool True if this request exceeds the configured limit
		 */
		public function isExceeded(): bool {
			return $this->exceeded;
		}

		/**
		 * @return int Unix timestamp (seconds) when the limit resets
		 */
		public function getResetTime(): int {
			return $this->resetTime;
		}

		/**
		 * @return int Seconds the client should wait before retrying; 0 when not exceeded
		 */
		public function getRetryAfter(): int {
			return $this->retryAfter;
		}
	}
