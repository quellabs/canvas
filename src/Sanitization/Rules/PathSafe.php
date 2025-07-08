<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This class implements path sanitization by removing common path traversal
	 * patterns and null bytes that could be used to access files outside
	 * the intended directory structure.
	 */
	class PathSafe implements SanitizationRuleInterface {
		
		/**
		 * Sanitize a value to make it safe for use in file paths
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value, or original value if not a string
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - return other types unchanged
			if (!is_string($value)) {
				return $value;
			}
			
			// Remove path traversal attempts (directory traversal patterns)
			// This prevents attackers from using ../ or ..\ to navigate up directories
			$value = str_replace(['../', '..\\', '../', '..\\'], '', $value);
			
			// Remove null bytes (\0) which can be used to truncate paths
			// in some systems and bypass security checks
			return str_replace("\0", '', $value);
		}
	}