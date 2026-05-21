<?php
	
	namespace Quellabs\Canvas\Validation\Contracts;
	
	/**
	 * @phpstan-type ValidationNode ValidationRuleInterface|list<ValidationRuleInterface>
	 */
	interface ValidationInterface {
		
		/**
		 * Returns an array of validation rules.
		 * @return array<string, ValidationNode|array<mixed>>
		 */
		public function getRules(): array;
	}