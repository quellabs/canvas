<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	/**
	 * NotBlank validation rule class
	 *
	 * Validates that a value is not blank (contains non-whitespace characters).
	 * This rule trims whitespace from the value and ensures the resulting string
	 * has a length greater than 0.
	 */
	class NotBlank extends RulesBase {
		
		/**
		 * Validates that the given value is not blank
		 * @param mixed $value The value to validate
		 * @return bool True if the value is not blank, false otherwise
		 */
		public function validate(mixed $value): bool {
			// Trim whitespace and check if the resulting string has content
			return strlen(trim($value)) > 0;
		}
		
		/**
		 * Returns the error message for validation failure
		 * @return string The error message to display when validation fails
		 */
		public function getError(): string {
			// Check if a custom error message was provided in conditions
			if (is_null($this->message)) {
				return "This value should not be blank";
			}
			
			// Return the custom error message
			return $this->message;
		}
	}