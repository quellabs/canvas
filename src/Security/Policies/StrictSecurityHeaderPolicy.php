<?php

	namespace Quellabs\Canvas\Security\Policies;

	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * The strict tier of Canvas's three built-in SecurityHeaderPolicyInterface
	 * implementations (BasicSecurityHeaderPolicy / MediumSecurityHeaderPolicy / strict).
	 * Denies all framing, a locked-down CSP, a 2-year preloaded HSTS, no referrer
	 * leakage, and the modern cross-origin isolation headers on top of
	 * BasicSecurityHeaderPolicy's set: Permissions-Policy, Cross-Origin-Opener-Policy,
	 * Cross-Origin-Resource-Policy, and X-Permitted-Cross-Domain-Policies.
	 *
	 * Deliberately leaves out Cross-Origin-Embedder-Policy: require-corp, since it
	 * breaks any cross-origin embed/image that doesn't opt in via CORS, and that's
	 * too likely to be a silent breakage for a built-in default.
	 */
	class StrictSecurityHeaderPolicy extends BasicSecurityHeaderPolicy {

		/** @var bool Include subdomains in HSTS */
		private bool $hstsIncludeSubdomains;

		/** @var string Permissions-Policy value */
		private string $permissionsPolicy;

		/** @var string Cross-Origin-Opener-Policy value */
		private string $crossOriginOpenerPolicy;

		/** @var string Cross-Origin-Resource-Policy value */
		private string $crossOriginResourcePolicy;

		/** @var string X-Permitted-Cross-Domain-Policies value */
		private string $permittedCrossDomainPolicies;

		/**
		 * Constructor
		 * @param string $frameOptions X-Frame-Options value (DENY, SAMEORIGIN, or ALLOW-FROM)
		 * @param bool $noSniff Enable X-Content-Type-Options: nosniff
		 * @param int $hstsMaxAge HSTS max-age in seconds (0 disables HSTS)
		 * @param bool $hstsIncludeSubdomains Include subdomains in HSTS
		 * @param bool $hstsPreload Add the preload directive to HSTS
		 * @param string $referrerPolicy Referrer-Policy value
		 * @param string|null $csp Content-Security-Policy value (null disables CSP)
		 * @param string $permissionsPolicy Permissions-Policy value
		 * @param string $crossOriginOpenerPolicy Cross-Origin-Opener-Policy value
		 * @param string $crossOriginResourcePolicy Cross-Origin-Resource-Policy value
		 * @param string $permittedCrossDomainPolicies X-Permitted-Cross-Domain-Policies value
		 */
		public function __construct(
			string $frameOptions = 'DENY',
			bool   $noSniff = true,
			int    $hstsMaxAge = 63072000, // 2 years
			bool   $hstsIncludeSubdomains = true,
			bool   $hstsPreload = true,
			string $referrerPolicy = 'no-referrer',
			?string $csp = "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
			string $permissionsPolicy = 'geolocation=(), camera=(), microphone=()',
			string $crossOriginOpenerPolicy = 'same-origin',
			string $crossOriginResourcePolicy = 'same-origin',
			string $permittedCrossDomainPolicies = 'none'
		) {
			parent::__construct(
				$frameOptions,
				$noSniff,
				$hstsMaxAge,
				$hstsPreload,
				$referrerPolicy,
				$csp
			);

			$this->hstsIncludeSubdomains = $hstsIncludeSubdomains;
			$this->permissionsPolicy = $permissionsPolicy;
			$this->crossOriginOpenerPolicy = $crossOriginOpenerPolicy;
			$this->crossOriginResourcePolicy = $crossOriginResourcePolicy;
			$this->permittedCrossDomainPolicies = $permittedCrossDomainPolicies;
		}

		/**
		 * Applies BasicSecurityHeaderPolicy's set, then the additional strict-tier headers
		 * @param Request $request The request, needed to decide HSTS eligibility (HTTPS only)
		 * @param Response $response The response to modify
		 * @return void
		 */
		public function apply(Request $request, Response $response): void {
			parent::apply($request, $response);

			if (!$response->headers->has('Permissions-Policy')) {
				$response->headers->set('Permissions-Policy', $this->permissionsPolicy);
			}

			if (!$response->headers->has('Cross-Origin-Opener-Policy')) {
				$response->headers->set('Cross-Origin-Opener-Policy', $this->crossOriginOpenerPolicy);
			}

			if (!$response->headers->has('Cross-Origin-Resource-Policy')) {
				$response->headers->set('Cross-Origin-Resource-Policy', $this->crossOriginResourcePolicy);
			}

			if (!$response->headers->has('X-Permitted-Cross-Domain-Policies')) {
				$response->headers->set('X-Permitted-Cross-Domain-Policies', $this->permittedCrossDomainPolicies);
			}
		}

		/**
		 * Builds the Strict-Transport-Security header value, adding includeSubDomains
		 * @return string
		 */
		protected function buildHstsValue(): string {
			$hsts = "max-age={$this->hstsMaxAge}";

			if ($this->hstsIncludeSubdomains) {
				$hsts .= '; includeSubDomains';
			}

			if ($this->hstsPreload) {
				$hsts .= '; preload';
			}

			return $hsts;
		}
	}
