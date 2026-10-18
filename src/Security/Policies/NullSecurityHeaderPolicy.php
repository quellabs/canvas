<?php

	namespace Quellabs\Canvas\Security\Policies;

	use Quellabs\Canvas\Security\SecurityHeaderPolicyInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * A no-op SecurityHeaderPolicyInterface implementation. Configure this as
	 * config/app.php's security_header_policy, or as SecurityHeadersAspect's
	 * policyClass on a specific route, to explicitly opt out of security
	 * headers rather than leaving the setting unset.
	 */
	class NullSecurityHeaderPolicy implements SecurityHeaderPolicyInterface {

		/**
		 * Does nothing; this policy adds no headers
		 * @param Request $request The HTTP request
		 * @param Response $response The HTTP response
		 * @return void
		 */
		public function apply(Request $request, Response $response): void {
		}
	}
