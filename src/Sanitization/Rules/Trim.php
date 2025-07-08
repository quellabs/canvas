<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This rule implements the SanitizationRuleInterface to provide
	 * whitespace trimming functionality for string inputs while
	 * preserving non-string values unchanged.
	 */
	class Trim implements SanitizationRuleInterface {
		
		/**
		 * Sanitize the input value by trimming whitespace from strings
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value (trimmed if a string, unchanged otherwise)
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - other types are returned as-is
			if (!is_string($value)) {
				return $value;
			}
			
			return trim($value);
		}
	}