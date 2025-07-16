<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This class implements the SanitizationRuleInterface to provide
	 * zero-width and invisible character removal functionality for
	 * text cleaning and security purposes.
	 *
	 * It removes invisible Unicode characters that can cause display
	 * issues, interfere with string comparisons, or be used in
	 * obfuscation attacks.
	 */
	class RemoveZeroWidth implements SanitizationRuleInterface {
		
		/**
		 * Sanitize the given value by removing zero-width and invisible characters
		 *
		 * This method removes various invisible Unicode characters including:
		 * - Zero Width Space (U+200B)
		 * - Zero Width Non-Joiner (U+200C)
		 * - Zero Width Joiner (U+200D)
		 * - Zero Width No-Break Space / Byte Order Mark (U+FEFF)
		 * - Left-to-Right Mark (U+200E)
		 * - Right-to-Left Mark (U+200F)
		 * - Word Joiner (U+2060)
		 * - Invisible Separator (U+2063)
		 * - Invisible Plus (U+2064)
		 *
		 * These characters can interfere with text processing, cause unexpected
		 * display behavior, and potentially be used for text obfuscation attacks.
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
			
			// Define pattern for zero-width and invisible Unicode characters
			// This covers the most common problematic invisible characters
			$invisibleChars = [
				'\x{200B}',  // Zero Width Space
				'\x{200C}',  // Zero Width Non-Joiner
				'\x{200D}',  // Zero Width Joiner
				'\x{200E}',  // Left-to-Right Mark
				'\x{200F}',  // Right-to-Left Mark
				'\x{2060}',  // Word Joiner
				'\x{2061}',  // Function Application (invisible)
				'\x{2062}',  // Invisible Times
				'\x{2063}',  // Invisible Separator
				'\x{2064}',  // Invisible Plus
				'\x{FEFF}',  // Zero Width No-Break Space / BOM
			];
			
			// Create regex pattern to match any of these characters
			$pattern = '/[' . implode('', $invisibleChars) . ']/u';
			
			// Remove all invisible characters from the string
			return preg_replace($pattern, '', $value);
		}
	}