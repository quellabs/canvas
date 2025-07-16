<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This class implements the SanitizationRuleInterface to provide
	 * null byte removal functionality for security and data integrity
	 * purposes.
	 *
	 * It removes null bytes (0x00) from input strings to prevent
	 * null byte injection attacks, file path manipulation, and
	 * string truncation issues in various systems.
	 */
	class RemoveNullBytes implements SanitizationRuleInterface {
		
		/**
		 * Sanitize the given value by removing null bytes
		 *
		 * This method removes all null bytes (character code 0, \0, 0x00)
		 * from the input string. Null bytes can cause security vulnerabilities
		 * and unexpected behavior including:
		 *
		 * - File path manipulation (directory traversal bypass)
		 * - String truncation in C-based functions
		 * - SQL injection in some database drivers
		 * - Application logic bypass through premature string termination
		 * - Log injection and output corruption
		 * - Buffer overflow exploitation in some contexts
		 *
		 * Many programming languages and systems treat null bytes as string
		 * terminators, which can lead to security vulnerabilities when user
		 * input containing null bytes is processed by such systems.
		 *
		 * @param mixed $value The value to sanitize (expected to be a string)
		 * @return mixed The sanitized value or original value if not a string
		 */
		public function sanitize(mixed $value): mixed {
			// Check if the input value is a string
			// If not, return the original value unchanged
			if (!is_string($value)) {
				return $value;
			}
			
			// Remove all null bytes from the string
			// This handles the null byte character (0x00) that can cause
			// security issues and unexpected string termination
			return str_replace("\0", '', $value);
		}
	}