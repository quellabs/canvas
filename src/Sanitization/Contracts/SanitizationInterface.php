<?php
	
	namespace Quellabs\Canvas\Sanitization\Contracts;
	
	/**
	 * Interface for validation rule providers
	 */
	interface SanitizationInterface {
		
		/**
		 * Returns an array of sanitization rules.
		 * @return array<string, mixed>
		 */
		public function getRules(): array;
	}