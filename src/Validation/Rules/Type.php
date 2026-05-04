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
		
		/** @var string The error message for the last validation failure */
		protected string $defaultMessage = "";
		
		/** @var list<string> Types validated using PHP's is_* functions */
		private const array IS_A_TYPES = [
			'bool', 'boolean',
			'int', 'integer', 'long',
			'float', 'double', 'real',
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
		
		/** @var list<string> Types validated using PHP's ctype_* functions */
		private const array CTYPE_TYPES = [
			'alnum',  // alphanumeric
			'alpha',  // alphabetic
			'cntrl',  // control characters
			'digit',  // digits
			'graph',  // printable characters (excluding spaces)
			'lower',  // lowercase letters
			'print',  // printable characters (including spaces)
			'punct',  // punctuation
			'space',  // whitespace
			'upper',  // uppercase letters
			'xdigit', // hexadecimal digits
		];
		
		/**
		 * Type constructor
		 * @param string $type The type identifier to validate against (e.g. 'string', 'int', 'alpha')
		 * @param string|null $message Custom error message to return on validation failure
		 * @throws \InvalidArgumentException If $type is not a supported is_* or ctype_* type
		 */
		public function __construct(string $type, ?string $message = null) {
			parent::__construct($message);
			
			if (!in_array($type, self::IS_A_TYPES, true) && !in_array($type, self::CTYPE_TYPES, true)) {
				throw new \InvalidArgumentException("Unsupported type '{$type}'");
			}
			
			$this->type = $type;
		}
		
		/**
		 * Validates the given value against the specified type.
		 *
		 * Empty string values are skipped, allowing optional fields to pass through.
		 * For is_* types the value is checked as-is; for ctype_* types it is cast
		 * to string first.
		 *
		 * @param mixed $value The value to validate
		 * @return bool True if validation passes, false otherwise
		 */
		public function validate(mixed $value): bool {
			// Skip validation for empty values (allows optional fields)
			if ($value === null || $value === '') {
				return true;
			}
			
			// Handle types that use PHP's is_* functions (e.g., is_string, is_int)
			if (in_array($this->type, self::IS_A_TYPES, true)) {
				if (!$this->getIsTypeValidator($this->type)($value)) {
					$this->defaultMessage = "This value should be of type {$this->type}";
					return false;
				}
			}
			
			// Handle types that use PHP's ctype_* functions (e.g., ctype_alpha, ctype_digit)
			if (in_array($this->type, self::CTYPE_TYPES, true)) {
				if (!$this->getCtypeValidator($this->type)((string)$value)) {
					$this->defaultMessage = $this->getCtypeErrorMessage($this->type);
					return false;
				}
			}
			
			// Validation passed
			return true;
		}
		
		/**
		 * Returns the error message for the last validation failure.
		 * @return string The custom message if one was provided at construction, otherwise the default message
		 */
		public function getError(): string {
			return $this->message ?? $this->defaultMessage;
		}
		
		/**
		 * Returns a validator callable for PHP native is_* style type checks.
		 * @param string $type The type identifier to validate against
		 * @return callable(mixed): bool A callable that returns true if the value matches the type
		 * @throws \LogicException If the provided type is not supported
		 */
		private function getIsTypeValidator(string $type): callable {
			return match ($type) {
				'bool', 'boolean' => fn($v) => is_bool($v),
				'int', 'integer', 'long' => fn($v) => is_int($v),
				'float', 'double', 'real' => fn($v) => is_float($v),
				'numeric' => fn($v) => is_numeric($v),
				'string' => fn($v) => is_string($v),
				'scalar' => fn($v) => is_scalar($v),
				'array' => fn($v) => is_array($v),
				'iterable' => fn($v) => is_iterable($v),
				'countable' => fn($v) => is_countable($v),
				'callable' => fn($v) => is_callable($v),
				'object' => fn($v) => is_object($v),
				'resource' => fn($v) => is_resource($v),
				'null' => fn($v) => is_null($v),
				default => throw new \LogicException("Unsupported type '{$type}'")
			};
		}
		
		/**
		 * Returns a validator callable for PHP native ctype_* style character-class checks.
		 *
		 * The returned callable expects a non-empty string and returns true only if
		 * every character in the string belongs to the specified character class.
		 *
		 * @param string $type The ctype identifier (e.g. 'alpha', 'digit', 'xdigit')
		 * @return callable(string): bool A callable that returns true if the string matches the character class
		 * @throws \LogicException If the provided type is not a supported ctype_* type
		 */
		private function getCtypeValidator(string $type): callable {
			return match ($type) {
				'alnum' => fn(string $v) => ctype_alnum($v),
				'alpha' => fn(string $v) => ctype_alpha($v),
				'cntrl' => fn(string $v) => ctype_cntrl($v),
				'digit' => fn(string $v) => ctype_digit($v),
				'graph' => fn(string $v) => ctype_graph($v),
				'lower' => fn(string $v) => ctype_lower($v),
				'print' => fn(string $v) => ctype_print($v),
				'punct' => fn(string $v) => ctype_punct($v),
				'space' => fn(string $v) => ctype_space($v),
				'upper' => fn(string $v) => ctype_upper($v),
				'xdigit' => fn(string $v) => ctype_xdigit($v),
				default => throw new \LogicException("Unsupported ctype '{$type}'")
			};
		}
		
		/**
		 * Returns the human-readable error message for a given ctype validation failure.
		 * @param string $type The ctype identifier that failed validation
		 * @return string A descriptive error message suitable for display to end users
		 */
		private function getCtypeErrorMessage(string $type): string {
			return match ($type) {
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
				'xdigit' => 'This value should contain only hexadecimal digits.',
				default => 'Invalid format.'
			};
		}
	}