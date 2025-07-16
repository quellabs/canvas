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
			
			// Remove event handlers (e.g., onclick="malicious()", onload="evil()")
			// Matches "on" followed by word characters and optional whitespace, then "="
			$value = preg_replace_callback(
				'/<([^>]+)>/i',
				function($matches) {
                    // Fetch content within < and >
					$tagContent = $matches[1];
					
					// Remove javascript: protocols (e.g., javascript:alert('xss'))
					// This prevents execution of JavaScript in href attributes and similar contexts
					$tagContent = preg_replace('/javascript:/i', '', $tagContent);
					
					// Remove event handlers within this tag
					$tagContent = preg_replace('/\s+on\w+\s*=\s*"[^"]*"/i', '', $tagContent);
					$tagContent = preg_replace('/\s+on\w+\s*=\s*\'[^\']*\'/i', '', $tagContent);
					$tagContent = preg_replace('/\s+on\w+\s*=\s*[^\s>]+/i', '', $tagContent);
					
                    // Return new content
					return '<' . $tagContent . '>';
				},
				$value
			);
            
            // Remove script tags and their content
			$value = preg_replace('/<\s*script[^>]*>.*?<\s*\/\s*script\s*>/is', '', $value);

            // Remove any remaining self-closing script tags
			$value = preg_replace('/<\s*script[^>]*\/?>/i', '', $value);

            // Remove any orphaned closing script tags
			return preg_replace('/<\s*\/\s*script\s*>/i', '', $value);
		}
	}