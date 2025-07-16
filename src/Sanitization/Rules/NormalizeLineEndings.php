<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This class implements the SanitizationRuleInterface to provide
	 * line ending normalization functionality for cross-platform
	 * compatibility and consistent data storage.
	 *
	 * It converts all line ending variations (Windows CRLF, classic Mac CR,
	 * and Unix LF) to a consistent Unix-style LF (\n) format.
	 */
	class NormalizeLineEndings implements SanitizationRuleInterface {
		
		/**
		 * Sanitize the given value by normalizing line endings
		 *
		 * This method converts all line ending variations to Unix-style
		 * line feeds (\n) for consistency:
		 * - Windows CRLF (\r\n) → Unix LF (\n)
		 * - Classic Mac CR (\r) → Unix LF (\n)
		 * - Mixed line endings → Consistent Unix LF (\n)
		 *
		 * This ensures consistent behavior across different operating systems
		 * and prevents issues with text processing, database storage, and
		 * display formatting.
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
			
			// Convert Windows line endings (CRLF) to Unix (LF) first
			// This must be done before converting standalone CR to prevent
			// double conversion of CRLF sequences
			$normalized = str_replace("\r\n", "\n", $value);
			
			// Convert any remaining carriage returns (classic Mac style) to Unix LF
			// This handles standalone \r characters that weren't part of \r\n pairs
			return str_replace("\r", "\n", $normalized);
		}
	}