<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	class NotLongWord extends RulesBase {
		
		/**
		 * Max length of each word
		 * @var int
		 */
		protected int $length;
		
		/**
		 * NotLongWord constructor
		 * @param int $length
		 */
		public function __construct(int $length = 30, ?string $message = null) {
			parent::__construct($message);
			$this->length = $length;
			$this->message = $message;
		}
		
		/**
		 * Check if any of the words in the text are longer than the specified length.
		 * If so, return false to signify that the validation failed.
		 * @param mixed $value
		 * @return bool
		 */
		public function validate(mixed $value): bool {
			// do not check if value empty
			if (($value === "") || is_null($value)) {
				return true;
			}
			
			// check all words and return false if any of them exceeds the length
			$words = explode(' ', $value);
			
			foreach ($words as $value) {
				if (mb_strlen($value, 'utf8') > $this->length) {
					return false;
				}
			}
			
			return true;
		}
		
		public function getError(): string {
			if (is_null($this->message)) {
				return "One of the words exceeds the length of {$this->length}.";
			}
			
			return $this->replaceVariablesInErrorString($this->message, [
				"length" => $this->length,
			]);
		}
	}