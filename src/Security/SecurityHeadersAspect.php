<?php
	
	namespace Quellabs\Canvas\Security;
	
	use Quellabs\Canvas\AOP\Contracts\AfterAspectInterfaceInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Security Headers Aspect
	 *
	 * Automatically adds security-related HTTP headers to protect against common attacks.
	 * Implements OWASP security header recommendations for web applications.
	 *
	 * Headers added:
	 * - X-Content-Type-Options: Prevents MIME type sniffing
	 * - X-Frame-Options: Prevents clickjacking attacks
	 * - X-XSS-Protection: Enables browser XSS filtering
	 * - Strict-Transport-Security: Enforces HTTPS connections
	 * - Referrer-Policy: Controls referrer information
	 * - Content-Security-Policy: Prevents XSS and data injection
	 */
	class SecurityHeadersAspect implements AfterAspectInterfaceInterface {
		
		/** @var string X-Frame-Options value (DENY, SAMEORIGIN, or ALLOW-FROM) */
		private string $frameOptions;
		
		/** @var bool Enable X-Content-Type-Options: nosniff */
		private bool $noSniff;
		
		/** @var bool Enable X-XSS-Protection: 1; mode=block */
		private bool $xssProtection;
		
		/** @var int HSTS max-age in seconds (0 disables HSTS) */
		private int $hstsMaxAge;
		
		/** @var bool Include subdomains in HSTS */
		private bool $hstsIncludeSubdomains;
		
		/** @var string Referrer-Policy value */
		private string $referrerPolicy;
		
		/** @var string|null Content-Security-Policy value (null disables CSP) */
		private ?string $csp;
		
		/**
		 * Constructor
		 * @param string $frameOptions X-Frame-Options value (DENY, SAMEORIGIN, or ALLOW-FROM)
		 * @param bool $noSniff Enable X-Content-Type-Options: nosniff
		 * @param bool $xssProtection Enable X-XSS-Protection: 1; mode=block
		 * @param int $hstsMaxAge HSTS max-age in seconds (0 disables HSTS)
		 * @param bool $hstsIncludeSubdomains Include subdomains in HSTS
		 * @param string $referrerPolicy Referrer-Policy value
		 * @param string|null $csp Content-Security-Policy value (null disables CSP)
		 */
		public function __construct(
			string  $frameOptions = 'SAMEORIGIN',
			bool    $noSniff = true,
			bool    $xssProtection = true,
			int     $hstsMaxAge = 31536000, // 1 year
			bool    $hstsIncludeSubdomains = true,
			string  $referrerPolicy = 'strict-origin-when-cross-origin',
			?string $csp = null
		) {
			$this->frameOptions = $frameOptions;
			$this->noSniff = $noSniff;
			$this->xssProtection = $xssProtection;
			$this->hstsMaxAge = $hstsMaxAge;
			$this->hstsIncludeSubdomains = $hstsIncludeSubdomains;
			$this->referrerPolicy = $referrerPolicy;
			$this->csp = $csp;
		}
		
		/**
		 * Adds security headers to the response after the controller method executes
		 * @param MethodContextInterface $context The method execution context
		 * @param Response $response The response to modify
		 */
		public function after(MethodContextInterface $context, Response $response): void {
			$this->addFrameOptions($response);
			$this->addContentTypeOptions($response);
			$this->addXssProtection($response);
			$this->addHsts($response, $context->getRequest());
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
		 * Adds X-XSS-Protection header for browser XSS filtering
		 * @param Response $response The HTTP response
		 * @return void
		 */
		private function addXssProtection(Response $response): void {
			if ($this->xssProtection && !$response->headers->has('X-XSS-Protection')) {
				$response->headers->set('X-XSS-Protection', '1; mode=block');
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
				$hsts = "max-age={$this->hstsMaxAge}";
				
				if ($this->hstsIncludeSubdomains) {
					$hsts .= '; includeSubDomains';
				}
				
				$response->headers->set('Strict-Transport-Security', $hsts);
			}
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