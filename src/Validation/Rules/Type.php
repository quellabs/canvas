<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	/**
	 * Type validation rule class
	 *
	 * Validates that a value matches a specified type using PHP's built-in type checking functions.
	 * Supports both is_* functions (e.g., is_string, is_int) and ctype_* functions (e.g., ctype_alpha, ctype_digit).
	 */
	class Type extends RulesBase {
		
		/** @var string The type to check */
		private string $type;
		
		/** @var string The error message when validation fails */
		protected string $defaultMessage = "";
		
		/** @var array List of types that can be checked using is_* functions */
		protected array $is_a_types;
		
		/** @var array List of types that can be checked using ctype_* functions */
		protected array $ctype_types;
		
		/**
		 * Type constructor
		 * @param string $type
		 * @param string|null $message
		 */
		public function __construct(string $type, ?string $message=null) {
			parent::__construct($message);
			$this->type = $type;
			
			// Define types that can be validated using PHP's is_* functions
			$this->is_a_types = [
				'bool',
				'boolean',
				'int',
				'integer',
				'long',
				'float',
				'double',
				'real',
				'numeric',
				'string',
				'scalar',
				'array',
				'iterable',
				'countable',
				'callable',
				'object',
				'resource',
				'null',
			];
			
			// Define types that can be validated using PHP's ctype_* functions
			$this->ctype_types = [
				'alnum',    // alphanumeric
				'alpha',    // alphabetic
				'cntrl',    // control characters
				'digit',    // digits
				'graph',    // printable characters (excluding spaces)
				'lower',    // lowercase letters
				'print',    // printable characters (including spaces)
				'punct',    // punctuation
				'space',    // whitespace
				'upper',    // uppercase letters
				'xdigit',   // hexadecimal digits
			];
		}
		
		/**
		 * Validates the given value against the specified type
		 * @param mixed $value The value to validate
		 * @return bool True if validation passes, false otherwise
		 */
		public function validate(mixed $value): bool {
			// Skip validation for empty values (allows optional fields)
			if ($value == '') {
				return true;
			}
			
			// Skip validation if no type is specified in conditions
			if (!isset($this->type)) {
				return true;
			}
			
			// Handle types that use PHP's is_* functions (e.g., is_string, is_int)
			if (in_array($this->type, $this->is_a_types)) {
				if (!call_user_func("is_{$this->type}", $value)) {
					$this->defaultMessage = "This value should be of type {$this->type}";
					return false;
				}
			}
			
			// Handle types that use PHP's ctype_* functions (e.g., ctype_alpha, ctype_digit)
			if (in_array($this->type, $this->ctype_types)) {
				// Define user-friendly error messages for each ctype validation
				$errorMessages = [
					'alnum' => 'This value should contain only alphanumeric characters.',
					'alpha' => 'This value should contain only alphabetic characters.',
					'cntrl' => 'This value should contain only control characters.',
					'digit' => 'This value should contain only digits.',
					'graph' => 'This value should contain only printable characters, excluding spaces.',
					'lower' => 'This value should contain only lowercase letters.',
					'print' => 'This value should contain only printable characters, including spaces.',
					'punct' => 'This value should contain only punctuation characters.',
					'space' => 'This value should contain only whitespace characters.',
					'upper' => 'This value should contain only uppercase letters.',
					'xdigit' => 'This value should contain only hexadecimal digits.'
				];
				
				// Perform the ctype validation
				if (!call_user_func("ctype_{$this->type}", $value)) {
					$this->defaultMessage = $errorMessages[$this->type];
					return false;
				}
			}
			
			// Validation passed
			return true;
		}
		
		/**
		 * Returns the error message for the last validation failure
		 * @return string The error message (custom message if provided, otherwise default)
		 */
		public function getError(): string {
			// Return a custom error message if provided in conditions
			if (is_null($this->message)) {
				return $this->defaultMessage;
			}
			
			return $this->message;
		}
	}