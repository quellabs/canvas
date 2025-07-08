<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	/**
	 * Regular Expression Validation Rule
	 *
	 * This class validates input values against a regular expression pattern.
	 * It implements the ValidationRuleInterface to provide consistent validation behavior.
	 */
	class RegExp extends RulesBase {
		
		/**
		 * Regular expression pattern to check
		 * @var string
		 */
		protected string $pattern;
		
		/**
		 * RegExp constructor
		 *
		 * Initializes the validation rule with optional conditions.
		 * Expected conditions array format:
		 * - 'regexp': The regular expression pattern to match against
		 * - 'message': Optional custom error message
		 *
		 * @param string|null $message
		 */
		public function __construct(string $pattern, ?string $message=null) {
			parent::__construct($message);
			$this->pattern = $pattern;
		}
		
		/**
		 * Validates the given value against the regular expression pattern
		 *
		 * Returns true if:
		 * - Value is empty string, null, or the regexp condition is not set (passes validation)
		 * - The regular expression pattern matches the value
		 *
		 * @param mixed $value The value to validate
		 * @return bool True if validation passes, false otherwise
		 */
		public function validate(mixed $value): bool {
			// Allow empty values to pass validation (use NotBlank rule for mandatory fields)
			if (($value === "") || is_null($value) || empty($this->pattern)) {
				return true;
			}
			
			// Use preg_match to test the value against the regular expression
			// Returns true if the pattern matches, false if it doesn't match or if there's an error
			return preg_match($this->pattern, $value) !== false;
		}
		
		/**
		 * Returns the error message for validation failures
		 * @return string The error message (custom message if provided, default message otherwise)
		 */
		public function getError(): string {
			// Return a custom error message if provided
			if (!isset($this->message)) {
				return "Regular expression did not match.";
			}
			
			return $this->message;
		}
	}