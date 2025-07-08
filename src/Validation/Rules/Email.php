<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	/**
	 * Class Email
	 * Implementation of a validation rule for email addresses
	 */
	class Email extends RulesBase {
		
		/**
		 * Validates if the value is a valid email address
		 * @param mixed $value The value that needs to be validated
		 * @return bool True if the value is a valid email address, otherwise false
		 */
		public function validate(mixed $value): bool {
			// If the value is an empty string or null, it is considered valid
			if (($value === "") || is_null($value)) {
				return true;
			}
			
			// Check if the value is a valid email address
			return filter_var($value, FILTER_VALIDATE_EMAIL);
		}
		
		/**
		 * Retrieves the error message if the value is not valid
		 * @return string The error message
		 */
		public function getError(): string {
			// If no custom error message is set, use the default message
			if (is_null($this->message)) {
				return "This value is not a valid email address.";
			}
			
			// Return the custom error message
			return $this->message;
		}
	}