<?php

	namespace Quellabs\Canvas\Security;

	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Exceptions\StaleAuthenticationException;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Requires the request's authentication to have been proven recently — and
	 * optionally by a specific method — before a sensitive action runs.
	 *
	 * Auth-mechanism agnostic: reads 'auth_time' (Unix timestamp) and
	 * 'auth_methods' (string[], RFC 8176 names) request attributes set by
	 * whatever authenticator ran earlier in the chain. requiredMethods lets a
	 * credential renewed via a weaker flow (e.g. token refresh) be excluded
	 * from satisfying the check; there's no default exclusion, since Canvas
	 * neither issues nor refreshes credentials itself.
	 *
	 * Must run after the authenticator — before-aspects execute in
	 * declaration order. Instantiate twice for a two-tier policy:
	 *
	 * @InterceptWith(Quellabs\Canvas\Security\JwtAuthenticationAspect::class)
	 * @InterceptWith(Quellabs\Canvas\Security\StepUpAuthenticationAspect::class, maxAge=300, requiredMethods={"pwd"})
	 */
	readonly class StepUpAuthenticationAspect implements BeforeAspectInterface {

		/**
		 * Required freshness window in seconds
		 * @var int
		 */
		private int $maxAge;

		/**
		 * When non-empty, at least one must be present in auth_methods
		 * @var string[]
		 */
		private array $requiredMethods;

		/**
		 * If true, throws StaleAuthenticationException instead of writing to request attributes
		 * @var bool
		 */
		private bool $throwOnFailure;

		/**
		 * StepUpAuthenticationAspect constructor
		 * @param int $maxAge Required freshness window in seconds
		 * @param string[] $requiredMethods When non-empty, at least one must be present in auth_methods
		 * @param bool $throwOnFailure If true, throws StaleAuthenticationException instead of writing to request attributes
		 */
		public function __construct(
			int $maxAge = 300,
			array $requiredMethods = [],
			bool $throwOnFailure = false
		) {
			// A non-positive window can never be satisfied, which is almost
			// certainly misconfiguration rather than an intentional lockout
			if ($maxAge <= 0) {
				throw new \InvalidArgumentException("maxAge must be > 0, got {$maxAge}.");
			}

			$this->maxAge = $maxAge;
			$this->requiredMethods = $requiredMethods;
			$this->throwOnFailure = $throwOnFailure;
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
