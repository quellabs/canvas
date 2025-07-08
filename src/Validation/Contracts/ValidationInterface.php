<?php
	
	namespace Quellabs\Canvas\Validation\Contracts;
	
	/**
	 * Interface for validation rule providers
	 */
	interface ValidationInterface {
		
		/**
		 * Returns an array of validation rules.
		 * @return array An array of validation rules
		 */
		public function getRules(): array;
	}