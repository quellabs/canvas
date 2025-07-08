<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	/**
	 * PhoneNumber validation rule class
	 *
	 * Validates phone numbers by allowing only digits and common phone number formatting characters.
	 * This is a permissive validation that allows various international phone number formats.
	 */
	class PhoneNumber extends RulesBase {
		
		/**
		 * Validates a phone number value
		 *
		 * Performs validation by checking if the value contains only allowed characters:
		 * - Digits (0-9)
		 * - Spaces
		 * - Commas
		 * - Periods/dots
		 * - Hyphens/dashes
		 * - Plus sign (for country codes)
		 *
		 * @param mixed $value The value to validate
		 * @return bool True if valid or empty/null, false otherwise
		 */
		public function validate(mixed $value): bool {
			// Allow empty or null values to pass validation
			// This allows for optional phone number fields
			if (($value === "") || is_null($value)) {
				return true;
			}
			
			// Remove all characters except allowed phone number characters
			// Then compare with original value to see if anything was removed
			// If they match, the original contained only valid characters
			return strcmp(preg_replace('/[^0-9\s,.\-+]/', '', $value), $value) == 0;
		}
		
		/**
		 * Returns the error message for validation failure
		 * @return string The error message to display when validation fails
		 */
		public function getError(): string {
			// Check if a custom error message was provided in conditions
			if (is_null($this->message)) {
				// Return default error message if no custom message specified
				return "This value does not meet the criteria for a valid phone number.";
			}
			
			// Return the custom error message
			return $this->message;
		}
	}