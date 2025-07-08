<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This class implements the SanitizationRuleInterface to provide
	 * email sanitization functionality using PHP's built-in filter_var
	 * function with FILTER_SANITIZE_EMAIL filter.
	 */
	class EmailSafe implements SanitizationRuleInterface {
		
		/**
		 * Sanitize the given value for email safety
		 *
		 * This method removes all characters except letters, digits and
		 * !#$%&'*+-=?^_`{|}~@.[] from the input string to make it safe
		 * for use as an email address.
		 *
		 * @param mixed $value The value to sanitize (expected to be a string)
		 * @return mixed The sanitized value or original value if not a string
		 */
		public function sanitize(mixed $value): mixed {
			// Check if the input value is a string
			// If not, return the original value unchanged
			if (!is_string($value)) {
				return $value;
			}
			
			// Apply PHP's built-in email sanitization filter
			// This removes all characters except letters, digits and !#$%&'*+-=?^_`{|}~@.[]
			return filter_var($value, FILTER_SANITIZE_EMAIL);
		}
	}