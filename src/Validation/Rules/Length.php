<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	/**
	 * Length validation rule class
	 *
	 * Validates that a string value meets minimum and/or maximum length requirements.
	 * Supports configurable min/max length conditions and custom error messages.
	 */
	class Length extends RulesBase {
		
		/**
		 * Default error message set during validation
		 * @var string|null
		 */
		protected ?string $defaultMessage = "";
		
		/**
		 * Minimum value to check
		 * @var int|null
		 */
		private ?int $min;
		
		/**
		 * Maximum value to check
		 * @var int|null
		 */
		private ?int $max;
		
		/**
		 * Length constructor
		 * @param int|null $min
		 * @param int|null $max
		 * @param string|null $message
		 */
		public function __construct(?int $min = null, int $max = null, ?string $message = null) {
			parent::__construct($message);
			$this->min = $min;
			$this->max = $max;
		}
		
		/**
		 * Validates the provided value against length constraints
		 * @param mixed $value The value to validate (expected to be string)
		 * @return bool True if validation passes, false otherwise
		 */
		public function validate(mixed $value): bool {
			// Allow empty values and null to pass validation
			// This follows the principle that length validation should only
			// apply to non-empty values
			if (($value === "") || is_null($value)) {
				return true;
			}
			
			// Check the minimum length requirement if specified
			if (!is_null($this->min)) {
				if (strlen($value) < $this->min) {
					// Set default error message for minimum length violation
					$this->defaultMessage = "This value is too short. It should have {{ min }} characters or more.";
					return false;
				}
			}
			
			// Check the maximum length requirement if specified
			if (!is_null($this->max)) {
				if (strlen($value) > $this->max) {
					// Set default error message for maximum length violation
					$this->defaultMessage = "This value is too long. It should have {{ max }} characters or less.";
					return false;
				}
			}
			
			// Validation passed - value meets all length requirements
			return true;
		}
		
		/**
		 * Returns the appropriate error message
		 * @return string Either the custom message from conditions or the default error message
		 */
		public function getError(): string {
			// Return a custom error message if provided in conditions
			if (is_null($this->message)) {
				return $this->replaceVariablesInErrorString($this->defaultMessage, [
					"min" => $this->min,
					"max" => $this->max,
				]);
			}
			
			// Otherwise, return the default error message set during validation
			return $this->replaceVariablesInErrorString($this->message, [
				"min" => $this->min,
				"max" => $this->max,
			]);
		}
	}