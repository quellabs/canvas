<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	/**
	 * Validation rule that checks if at least one of the provided conditions is satisfied.
	 * This rule passes if any of the nested validation conditions returns true.
	 */
	class AtLeastOneOf extends RulesBase {
		
		/**
		 * Array of validation rule objects that will be tested
		 * @var array
		 */
		protected array $conditions;
		
		/**
		 * Constructor for AtLeastOneOf validation rule
		 * @param array $conditions Array of validation rule objects that implement ValidationRuleInterface
		 */
		public function __construct(array $conditions = [], ?string $message=null) {
			parent::__construct($message);
			$this->conditions = $conditions;
		}
		
		/**
		 * Validates the given value against all conditions
		 * Returns true if at least one condition passes
		 * @param mixed $value The value to validate
		 * @return bool True if at least one condition is satisfied, false otherwise
		 */
		public function validate(mixed $value): bool {
			// Counter to track how many conditions passed
			$counter = 0;
			
			// Iterate through each validation condition
			foreach($this->conditions as $condition) {
				// If this condition passes validation, increment counter
				if ($condition->validate($value)) {
					++$counter;
				}
			}
			
			// Return true if at least one condition passed (counter > 0)
			return $counter > 0;
		}
		
		/**
		 * Returns the error message when validation fails
		 * @return string The error message to display when validation fails
		 */
		public function getError(): string {
			// Check if a custom error message was provided in conditions array
			// Note: This logic seems incorrect - checking for "message" key in the conditions array
			// which contains validation rule objects, not a message string
			if (is_null($this->message)) {
				return "At least one of the conditions should be fulfilled.";
			}
			
			return $this->message;
		}
	}