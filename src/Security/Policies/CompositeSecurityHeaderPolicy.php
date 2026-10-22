<?php

	namespace Quellabs\Canvas\Security\Policies;

	use Quellabs\Canvas\Security\SecurityHeaderPolicyInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Applies an ordered list of SecurityHeaderPolicyInterface instances to the same
	 * response. Built by SecurityHeaderPolicyResolver when config/app.php's
	 * security_header_policy or SecurityHeadersAspect's policyClass is configured as
	 * a list of classes rather than a single one; policies should avoid overwriting
	 * headers already set by an earlier policy in the list.
	 */
	class CompositeSecurityHeaderPolicy implements SecurityHeaderPolicyInterface {

		/** @var SecurityHeaderPolicyInterface[] Policies applied to the response, in order */
		private array $policies;

		/**
		 * Constructor
		 * @param SecurityHeaderPolicyInterface[] $policies Validated policies, applied in order
		 */
		public function __construct(array $policies) {
			$this->policies = $policies;
		}

		/**
		 * Applies every policy to the response, in order
		 * @param Request $request The request, passed through to each policy
		 * @param Response $response The response to modify
		 * @return void
		 */
		public function apply(Request $request, Response $response): void {
			foreach ($this->policies as $policy) {
				$policy->apply($request, $response);
			}
		}
	}
