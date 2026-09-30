<?php

	namespace Quellabs\Canvas\Security;

	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Exceptions\StaleAuthenticationException;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Requires the request's authentication to have been proven recently — and
	 * optionally proven by a strong-enough method — for use on sensitive
	 * actions (change email, delete account, ...).
	 *
	 * Auth-mechanism agnostic: it only reads two request attributes that any
	 * authenticator aspect running earlier in the @InterceptWith chain is
	 * expected to set:
	 *   - 'auth_time'    Unix timestamp of when the credential was last proven
	 *   - 'auth_methods' string[] of methods used (RFC 8176 names recommended,
	 *                    e.g. 'pwd', 'hwk', 'otp'; empty when unknown)
	 * It does not know or care whether the authenticator is JWT-, session-, or
	 * API-key-based.
	 *
	 * requiredMethods is the equivalent of Symfony's AuthenticationTrustResolver
	 * extension point: a token renewed via a refresh flow rather than a fresh
	 * credential check (Symfony's remember-me case) can carry a method such as
	 * 'refresh' in auth_methods, and be excluded from satisfying a sensitive
	 * action by requiring e.g. requiredMethods=['pwd']. There is no default
	 * exclusion — unlike Symfony's security bundle, Canvas does not define a
	 * built-in "weak" method, since it doesn't issue or refresh tokens itself.
	 *
	 * Must run after whatever aspect sets these attributes — before-aspects
	 * execute in declaration order:
	 *
	 * @InterceptWith(Quellabs\Canvas\Security\JwtAuthenticationAspect::class)
	 * @InterceptWith(Quellabs\Canvas\Security\RecentAuthenticationAspect::class, maxAge=300, requiredMethods={"pwd"})
	 *
	 * The same class serves both "recently" and "very recently" tiers via the
	 * maxAge override — instantiate it twice rather than duplicating the check.
	 */
	readonly class RecentAuthenticationAspect implements BeforeAspectInterface {

		/**
		 * RecentAuthenticationAspect constructor
		 * @param int $maxAge Required freshness window in seconds
		 * @param string[] $requiredMethods When non-empty, at least one must be present in auth_methods
		 * @param bool $throwOnFailure If true, throws StaleAuthenticationException instead of writing to request attributes
		 */
		public function __construct(
			private int    $maxAge = 300,
			private array  $requiredMethods = [],
			private bool   $throwOnFailure = false
		) {
			// A non-positive window can never be satisfied, which is almost
			// certainly misconfiguration rather than an intentional lockout
			if ($this->maxAge <= 0) {
				throw new \InvalidArgumentException("maxAge must be > 0, got {$this->maxAge}.");
			}
		}

		/**
		 * Check the request's authentication freshness and method before the controller method runs.
		 *
		 * On failure in attribute mode: sets 'recent_auth_error' on $request->attributes, returns null.
		 * On failure in exception mode: throws StaleAuthenticationException.
		 *
		 * @param MethodContextInterface $context
		 * @return Response|null Always null — this aspect never short-circuits via Response.
		 * @throws StaleAuthenticationException When throwOnFailure is true and the check fails.
		 */
		public function before(MethodContextInterface $context): ?Response {
			$request = $context->getRequest();
			$authTime = $request->attributes->get('auth_time');
			$presentedMethods = $request->attributes->get('auth_methods', []);

			if (!is_array($presentedMethods)) {
				$presentedMethods = [];
			}

			$isRecent = is_numeric($authTime) && (time() - (int)$authTime) <= $this->maxAge;
			$hasRequiredMethod = empty($this->requiredMethods) || !empty(array_intersect($this->requiredMethods, $presentedMethods));

			if (!$isRecent || !$hasRequiredMethod) {
				if ($this->throwOnFailure) {
					throw new StaleAuthenticationException(
						maxAge: $this->maxAge,
						requiredMethods: $this->requiredMethods,
						presentedMethods: $presentedMethods,
						requestMethod: $request->getMethod(),
						requestPath: $request->getPathInfo()
					);
				}

				$request->attributes->set('recent_auth_error', $this->buildErrorMessage($isRecent, $hasRequiredMethod));
				return null;
			}

			$request->attributes->remove('recent_auth_error');
			return null;
		}

		/**
		 * Build a human-readable failure reason for attribute mode.
		 * @param bool $isRecent Whether the recency check passed
		 * @param bool $hasRequiredMethod Whether the method check passed
		 * @return string Reason the check failed
		 */
		private function buildErrorMessage(bool $isRecent, bool $hasRequiredMethod): string {
			if (!$isRecent) {
				return "Authentication must be renewed within {$this->maxAge} seconds";
			}

			return 'Authentication method does not meet the required strength for this action';
		}
	}
