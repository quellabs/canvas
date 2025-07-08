<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * Sanitizes input by escaping HTML special characters to prevent XSS attacks
	 * and ensure safe display of user-generated content in HTML contexts.
	 */
	class HtmlEscape implements SanitizationRuleInterface {
		
		/**
		 * Sanitize the given value by escaping HTML special characters
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value (HTML-escaped if string, unchanged otherwise)
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - other types are returned as-is
			if (!is_string($value)) {
				return $value;
			}
			
			// Escape HTML special characters using PHP's built-in function
			// ENT_QUOTES: Escapes both single and double quotes
			// ENT_HTML5: Uses HTML5 entity encoding standards
			// UTF-8: Ensures proper handling of Unicode characters
			return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
		}
	}