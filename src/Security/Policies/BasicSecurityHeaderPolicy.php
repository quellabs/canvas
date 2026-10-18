<?php

	namespace Quellabs\Canvas\Security\Policies;

	use Quellabs\Canvas\Security\SecurityHeaderPolicyInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;

	/**
	 * The basic tier of Canvas's three built-in SecurityHeaderPolicyInterface
	 * implementations (basic / MediumSecurityHeaderPolicy / StrictSecurityHeaderPolicy).
	 * Used as the application-wide default (config/app.php's security_header_policy)
	 * unless an application configures its own policy class, and as
	 * SecurityHeadersAspect's fallback when neither a policyClass override nor an
	 * application-wide default is configured.
	 *
	 * Every add* method only sets a header when one isn't already present, so
	 * a route-specific value set earlier always wins over this policy's own.
	 */
	class BasicSecurityHeaderPolicy implements SecurityHeaderPolicyInterface {

		/** @var string X-Frame-Options value (DENY, SAMEORIGIN, or ALLOW-FROM) */
		private string $frameOptions;

		/** @var bool Enable X-Content-Type-Options: nosniff */
		private bool $noSniff;

		/** @var int HSTS max-age in seconds (0 disables HSTS) */
		protected int $hstsMaxAge;

		/** @var bool Add the preload directive to HSTS */
		protected bool $hstsPreload;

		/** @var string Referrer-Policy value */
		private string $referrerPolicy;

		/** @var string|null Content-Security-Policy value (null disables CSP) */
		private ?string $csp;

		/**
		 * Constructor
		 * @param string $frameOptions X-Frame-Options value (DENY, SAMEORIGIN, or ALLOW-FROM)
		 * @param bool $noSniff Enable X-Content-Type-Options: nosniff
		 * @param int $hstsMaxAge HSTS max-age in seconds (0 disables HSTS)
		 * @param bool $hstsPreload Add the preload directive to HSTS
		 * @param string $referrerPolicy Referrer-Policy value
		 * @param string|null $csp Content-Security-Policy value (null disables CSP)
		 */
		public function __construct(
			string  $frameOptions = 'SAMEORIGIN',
			bool    $noSniff = true,
			int     $hstsMaxAge = 15552000, // 180 days
			bool    $hstsPreload = false,
			string  $referrerPolicy = 'strict-origin-when-cross-origin',
			?string $csp = null
		) {
			$this->frameOptions = $frameOptions;
			$this->noSniff = $noSniff;
			$this->hstsMaxAge = $hstsMaxAge;
			$this->hstsPreload = $hstsPreload;
			$this->referrerPolicy = $referrerPolicy;
			$this->csp = $csp;
		}

		/**
		 * Applies every configured security header to the response, in place
		 * @param Request $request The request, needed to decide HSTS eligibility (HTTPS only)
		 * @param Response $response The response to modify
		 * @return void
		 */
		public function apply(Request $request, Response $response): void {
			$this->addFrameOptions($response);
			$this->addContentTypeOptions($response);
			$this->addHsts($response, $request);
			$this->addReferrerPolicy($response);
			$this->addContentSecurityPolicy($response);
		}

		/**
		 * Adds X-Frame-Options header to prevent clickjacking
		 * @param Response $response The HTTP response
		 * @return void
		 */
		private function addFrameOptions(Response $response): void {
			if (!$response->headers->has('X-Frame-Options')) {
				$response->headers->set('X-Frame-Options', $this->frameOptions);
			}
		}

		/**
		 * Adds X-Content-Type-Options header to prevent MIME sniffing
		 * @param Response $response The HTTP response
		 * @return void
		 */
		private function addContentTypeOptions(Response $response): void {
			if ($this->noSniff && !$response->headers->has('X-Content-Type-Options')) {
				$response->headers->set('X-Content-Type-Options', 'nosniff');
			}
		}

		/**
		 * Adds Strict-Transport-Security header for HTTPS enforcement
		 * @param Response $response The HTTP response
		 * @param Request $request The HTTP request
		 * @return void
		 */
		private function addHsts(Response $response, Request $request): void {
			// Only add HSTS for HTTPS requests
			if ($this->hstsMaxAge > 0 && $request->isSecure() && !$response->headers->has('Strict-Transport-Security')) {
				$response->headers->set('Strict-Transport-Security', $this->buildHstsValue());
			}
		}

		/**
		 * Builds the Strict-Transport-Security header value. Overridden by subclasses that add directives.
		 * @return string
		 */
		protected function buildHstsValue(): string {
			$hsts = "max-age={$this->hstsMaxAge}";

			if ($this->hstsPreload) {
				$hsts .= '; preload';
			}

			return $hsts;
		}

		/**
		 * Adds Referrer-Policy header to control referrer information
		 * @param Response $response The HTTP response
		 * @return void
		 */
		private function addReferrerPolicy(Response $response): void {
			if (!$response->headers->has('Referrer-Policy')) {
				$response->headers->set('Referrer-Policy', $this->referrerPolicy);
			}
		}

		/**
		 * Adds Content-Security-Policy header if configured
		 * @param Response $response The HTTP response
		 * @return void
		 */
		private function addContentSecurityPolicy(Response $response): void {
			if ($this->csp && !$response->headers->has('Content-Security-Policy')) {
				$response->headers->set('Content-Security-Policy', $this->csp);
			}
		}
	}
