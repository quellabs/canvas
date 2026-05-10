<?php
	
	namespace Quellabs\Canvas\Exceptions;
	
	use RuntimeException;
	
	/**
	 * Thrown by CsrfProtectionAspect when throwOnFailure is enabled and
	 * the CSRF token is missing or invalid.
	 *
	 * The framework's exception handler is responsible for converting this
	 * into an appropriate HTTP response. Controllers that want to handle
	 * CSRF failure themselves (e.g. to re-render a form with an error message)
	 * should use the default attribute-based path instead of enabling throwOnFailure,
	 * or catch this exception explicitly in their own exception handler.
	 */
	class RateLimitException extends RuntimeException {
	
	}