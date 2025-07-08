<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	class ValueIn extends RulesBase {
		
		/**
		 * Values to check
		 * @var array
		 */
		private array $values;
		
		/**
		 * ValueIn constructor
		 * @param array $values
		 * @param string|null $message
		 */
		public function __construct(array $values, ?string $message=null) {
			parent::__construct($message);
			$this->values = $values;
		}
		
		/**
		 * Perform the validation
		 * @param mixed $value
		 * @return bool
		 */
		public function validate(mixed $value): bool {
			if (empty($this->values) || ($value == "") || ($value == null)) {
				return true;
			}
			
			return in_array($value, $this->values);
		}
		
		/**
		 * Returns error when validation fails
		 * @return string
		 */
		public function getError(): string {
			if (is_null($this->message)) {
				return "Value should be any of these: " . implode(",", array_map(function($e) { return "'{$e}'"; }, $this->values));
			}

			return $this->message;
		}
	}