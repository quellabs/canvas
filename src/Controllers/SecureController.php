<?php
	namespace Quellabs\Canvas\Controllers;
	
	use Quellabs\Canvas\Annotations\InterceptWith;
	use Quellabs\Canvas\Security\SecurityHeadersAspect;
	
	/**
	 * Base controller that automatically applies security headers to all methods.
	 * Extend this controller when you want comprehensive security protection.
	 *
	 * All methods in controllers extending SecureController automatically get:
	 * - X-Frame-Options: SAMEORIGIN
	 * - X-Content-Type-Options: nosniff
	 * - X-XSS-Protection: 1; mode=block
	 * - Strict-Transport-Security (HTTPS only)
	 * - Referrer-Policy: strict-origin-when-cross-origin
	 *
	 * @InterceptWith(SecurityHeadersAspect::class)
	 */
	abstract class SecureController extends BaseController {
	}