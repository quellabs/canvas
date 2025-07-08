<?php
	
	namespace Quellabs\Canvas\Validation\Contracts;
	
	/**
	 * Interface for validation rules in the Canvas Validation system
	 */
	interface ValidationRuleInterface {
		
		/**
		 * Validates the given value against this rule's criteria
		 * @param mixed $value The value to validate (can be any type depending on rule)
		 * @return bool True if validation passes, false if it fails
		 */
		public function validate(mixed $value) : bool;
		
		/**
		 * Gets the error message to display when validation fails
		 * @return string The error message for validation failure
		 */
		public function getError() : string;
	}