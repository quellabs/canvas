<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * ScriptSafe sanitization rule that removes potentially dangerous JavaScript code
	 * from user input to prevent XSS (Cross-Site Scripting) attacks.
	 */
	class ScriptSafe implements SanitizationRuleInterface {
		
		/**
		 * Sanitizes the input value by removing JavaScript-related security threats.
		 *
		 * This method removes:
		 * - javascript: protocol handlers
		 * - HTML event handlers (onclick, onload, etc.)
		 * - <script> tags and their contents
		 *
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value, or original value if not a string
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - other types are returned unchanged
			if (!is_string($value)) {
				return $value;
			}
			
			// Remove javascript: protocols (e.g., javascript:alert('xss'))
			// This prevents execution of JavaScript in href attributes and similar contexts
			$value = preg_replace('/javascript:/i', '', $value);
			
			// Remove event handlers (e.g., onclick="malicious()", onload="evil()")
			// Matches "on" followed by word characters and optional whitespace, then "="
			$value = preg_replace('/on\w+\s*=/i', '', $value);
			
			// Remove script tags and all content between them
			// Uses a complex regex to handle nested tags and multiline content
			// 'm' flag enables multiline matching, 'i' flag makes it case-insensitive
			return preg_replace('/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi', '', $value);
		}
	}