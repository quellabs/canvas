<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * Sanitization rule that normalizes whitespace characters in string values.
	 *
	 * This rule collapses multiple consecutive whitespace characters (spaces, tabs,
	 * newlines, etc.) into single spaces and trims leading/trailing whitespace.
	 * Non-string values are returned unchanged.
	 */
	class WhitespaceNormalize implements SanitizationRuleInterface {
		
		/**
		 * Sanitizes the input value by normalizing whitespace characters.
		 * - Collapses multiple consecutive whitespace characters into single spaces
		 * - Removes leading and trailing whitespace
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value with normalized whitespace, or original value if not a string
		 */
		public function sanitize(mixed $value): mixed {
			// Return non-string values unchanged
			if (!is_string($value)) {
				return $value;
			}
			
			// Replace multiple consecutive whitespace characters (spaces, tabs, newlines, etc.)
			// with a single space using regex pattern \s+ (one or more whitespace characters)
			$value = preg_replace('/\s+/', ' ', $value);
			
			// Remove leading and trailing whitespace
			return trim($value);
		}
	}