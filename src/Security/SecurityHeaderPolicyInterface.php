<?php

	namespace Quellabs\Canvas\Security;

	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * A security-header policy: anything that can decorate a response with
	 * security-related headers. Implemented by the built-in tiers in
	 * Quellabs\Canvas\Security\Policies (Basic/Medium/Strict) and by any
	 * application-specific policy class configured via config/app.php's
	 * security_header_policy or SecurityHeadersAspect's policyClass parameter.
	 */
	interface SecurityHeaderPolicyInterface {

		/**
		 * Applies this policy's security headers to the response, in place
		 * @param Request $request The request, e.g. needed to decide HSTS eligibility (HTTPS only)
		 * @param Response $response The response to modify
		 * @return void
		 */
		public function apply(Request $request, Response $response): void;
	}
