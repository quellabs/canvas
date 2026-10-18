<?php
	namespace Quellabs\Canvas\Controllers;

	use Quellabs\Canvas\Annotations\InterceptWith;
	use Quellabs\Canvas\Security\Policies\MediumSecurityHeaderPolicy;
	use Quellabs\Canvas\Security\SecurityHeadersAspect;

	/**
	 * Base controller that pins the medium security-header tier on all methods,
	 * regardless of whatever config/app.php's security_header_policy is set to.
	 * Extend this controller when you want this guaranteed, specific baseline -
	 * not "whatever the app-wide default happens to be".
	 *
	 * All methods in controllers extending SecureController get:
	 * - X-Frame-Options: SAMEORIGIN
	 * - X-Content-Type-Options: nosniff
	 * - Strict-Transport-Security, 2 years with subdomains included (HTTPS only)
	 * - Referrer-Policy: strict-origin
	 * - Content-Security-Policy: default-src 'self'
	 *
	 * @InterceptWith(SecurityHeadersAspect::class, policyClass=MediumSecurityHeaderPolicy::class)
	 */
	abstract class SecureController extends BaseController {
	}