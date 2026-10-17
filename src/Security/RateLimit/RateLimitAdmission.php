<?php

	namespace Quellabs\Canvas\Security\RateLimit;

	/**
	 * Pairs the state RateLimitMath wants persisted next with the admission
	 * result for the current request. Immutable value object: exists so callers
	 * read ->getState()/->getResult() by name instead of destructuring a tuple.
	 */
	final class RateLimitAdmission {

		/** @var array<string, mixed> State to persist for this key */
		private array $state;

		/** @var RateLimitResult Admission result for the current request */
		private RateLimitResult $result;

		/**
		 * @param array<string, mixed> $state State to persist for this key
		 * @param RateLimitResult $result Admission result for the current request
		 */
		public function __construct(array $state, RateLimitResult $result) {
			$this->state = $state;
			$this->result = $result;
		}

		/**
		 * @return array<string, mixed> State to persist for this key
		 */
		public function getState(): array {
			return $this->state;
		}

		/**
		 * @return RateLimitResult Admission result for the current request
		 */
		public function getResult(): RateLimitResult {
			return $this->result;
		}
	}
