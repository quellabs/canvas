<?php

	namespace Quellabs\Canvas\Security;

	use Quellabs\Canvas\AOP\Contracts\AfterAspectInterface;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * Security Headers Aspect
	 *
	 * Adds security-related HTTP headers to protect against common attacks, via
	 * a SecurityHeaderPolicyInterface: config/app.php's security_header_policy by
	 * default, or the $policyClass given here to override it for this route only.
	 *
	 * As an AfterAspectInterface, this only runs when the controller method it's
	 * attached to actually executes - a before-aspect short circuit on the same
	 * route returns its own response untouched, same as for any other after-aspect.
	 * A route miss or a thrown exception is covered by DefaultErrorHandler instead,
	 * using the same application-wide default policy; a before-aspect short circuit
	 * is neither - whatever short-circuited the route is responsible for its own headers.
	 */
	class SecurityHeadersAspect implements AfterAspectInterface {

		/** @var SecurityHeaderPolicyInterface Policy applied to the response */
		private SecurityHeaderPolicyInterface $policy;

		/**
		 * Constructor
		 * @param Kernel $kernel Supplies the application-wide default policy when $policyClass is null
		 * @param class-string<SecurityHeaderPolicyInterface>|null $policyClass Class implementing SecurityHeaderPolicyInterface to use for this route instead of the application-wide default
		 */
		public function __construct(Kernel $kernel, ?string $policyClass = null) {
			if ($policyClass === null) {
				$this->policy = $kernel->getDefaultSecurityHeaderPolicy();
				return;
			}

			$policy = $kernel->getDependencyInjector()->make($policyClass);

			if (!$policy instanceof SecurityHeaderPolicyInterface) {
				throw new \InvalidArgumentException(sprintf(
					"SecurityHeadersAspect's policyClass '%s' must implement %s.",
					$policyClass,
					SecurityHeaderPolicyInterface::class
				));
			}

			$this->policy = $policy;
		}

		/**
		 * Adds security headers to the response after the controller method executes
		 * @param MethodContextInterface $context The method execution context
		 * @param Response $response The response to modify
		 */
		public function after(MethodContextInterface $context, Response $response): void {
			// Fetch the request
			$request = $context->getRequest();
			
			// Apply the policy
			$this->policy->apply($request, $response);

			// Tells Kernel's blanket apply of the app-wide default to skip this
			// response: this route already got a policy, even NullSecurityHeaderPolicy
			// opting out on purpose, and that choice must not be overridden.
			$request->attributes->set('security_headers_applied', true);
		}
	}
