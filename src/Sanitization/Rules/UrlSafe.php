<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * URL sanitization rule that removes dangerous protocols and validates URLs
	 *
	 * This rule is designed to prevent XSS attacks and other security vulnerabilities
	 * by sanitizing URLs before they are processed or stored.
	 */
	class UrlSafe implements SanitizationRuleInterface {
		
		/**
		 * Sanitizes a URL by removing dangerous protocols and applying basic validation
		 * @param mixed $value The value to sanitize (expected to be a string URL)
		 * @return mixed The sanitized URL string, or the original value if not a string
		 */
		public function sanitize(mixed $value): mixed {
			// Return non-string values unchanged - they don't need URL sanitization
			if (!is_string($value)) {
				return $value;
			}
			
			// Remove dangerous protocols that could be used for XSS or other attacks
			// This prevents URLs like: javascript:alert('xss'), data:text/html,<script>...
			$value = preg_replace('/^(javascript|data|vbscript|file|ftp):/i', '', $value);
			
			// Apply PHP's built-in URL sanitization filter
			// This removes characters that are not allowed in URLs and encodes others
			return filter_var($value, FILTER_SANITIZE_URL);
		}
	}