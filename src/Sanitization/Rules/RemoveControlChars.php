<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * Sanitization rule that removes ASCII control characters from string values.
	 *
	 * This rule helps prevent potential security issues and data corruption by
	 * removing non-printable control characters while preserving commonly used
	 * whitespace characters like tabs, line feeds, and carriage returns.
	 */
	class RemoveControlChars implements SanitizationRuleInterface {
		
		/**
		 * Sanitizes the input value by removing ASCII control characters.
		 *
		 * Non-string values are returned unchanged. For string values, removes
		 * ASCII control characters (0-31 and 127) except for:
		 * - Tab (9)
		 * - Line Feed (10)
		 * - Carriage Return (13)
		 *
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value (unchanged if not a string)
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - return other types unchanged
			if (!is_string($value)) {
				return $value;
			}
			
			// Remove ASCII control characters (0-31) except tab (9), LF (10), CR (13)
			// Also removes DEL character (127)
			// Pattern explanation:
			// \x00-\x08: NULL through BACKSPACE
			// \x0B: VERTICAL TAB (excludes \x09 TAB and \x0A LF)
			// \x0C: FORM FEED (excludes \x0D CR)
			// \x0E-\x1F: SHIFT OUT through UNIT SEPARATOR
			// \x7F: DELETE character
			return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
		}
	}