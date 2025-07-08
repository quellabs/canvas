<?php
	
	namespace Quellabs\Canvas\Sanitization\Contracts;
	
	/**
	 * Interface for validation rule providers
	 */
	interface SanitizationInterface {
		
		/**
		 * Returns an array of validation rules.
		 * @return array An array of validation rules
		 */
		public function getRules(): array;
	}