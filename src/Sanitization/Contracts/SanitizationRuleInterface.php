<?php
	
	namespace Quellabs\Canvas\Sanitization\Contracts;
	
	/**
	 * This interface defines the contract that all sanitization rules must implement.
	 * Sanitization rules are responsible for cleaning and normalizing input data
	 * to ensure it meets specific criteria or format requirements.
	 */
	interface SanitizationRuleInterface {
		
		/**
		 * Sanitizes the given value according to this rule's criteria
		 *
		 * This method takes a value of any type and applies sanitization logic
		 * to clean, normalize, or transform the data. The specific sanitization
		 * behavior depends on the implementing class.
		 *
		 * Examples of sanitization might include:
		 * - Trimming whitespace from strings
		 * - Removing HTML tags
		 * - Converting to lowercase
		 * - Formatting phone numbers
		 * - Normalizing email addresses
		 *
		 * @param mixed $value The value to sanitize (can be any type depending on rule)
		 * @return mixed The sanitized value, type may vary based on implementation
		 */
		public function sanitize(mixed $value): mixed;
	}