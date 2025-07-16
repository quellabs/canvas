<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This class implements the SanitizationRuleInterface to provide
	 * style attribute removal functionality for security and content
	 * consistency purposes.
	 *
	 * It removes all style attributes from HTML elements to prevent
	 * CSS injection attacks, maintain design consistency, and ensure
	 * content adheres to the application's styling standards.
	 */
	class RemoveStyleAttributes implements SanitizationRuleInterface {
		
		/**
		 * Sanitize the given value by removing style attributes from HTML tags
		 *
		 * This method removes all style attributes from HTML elements including:
		 * - Inline styles: <div style="color: red; font-size: 12px;">
		 * - Style attributes with various quote types: style='...' or style="..."
		 * - Style attributes with whitespace variations: style = "..."
		 * - Malformed style attributes without quotes
		 * - Case variations: STYLE="..." or Style="..."
		 *
		 * The regex ensures that style attributes are only removed when they
		 * appear within actual HTML tags, not in regular text content.
		 *
		 * This prevents CSS injection attacks where malicious styles could:
		 * - Hide or obscure content (opacity: 0, display: none)
		 * - Create overlay attacks (position: absolute)
		 * - Load external resources (background: url(...))
		 * - Execute JavaScript in older browsers (expression(...))
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
			
			// Use callback to process each HTML tag and remove style attributes
			return preg_replace_callback(
				'/<([^>]+)>/i',
				function($matches) {
					$tagContent = $matches[1];
					
					// Remove style attributes with double quotes
					$tagContent = preg_replace('/\s+style\s*=\s*"[^"]*"/i', '', $tagContent);
					
					// Remove style attributes with single quotes
					$tagContent = preg_replace('/\s+style\s*=\s*\'[^\']*\'/i', '', $tagContent);
					
					// Remove style attributes without quotes (malformed)
					$tagContent = preg_replace('/\s+style\s*=\s*[^\s>]+/i', '', $tagContent);
					
					// Remove standalone style attribute names
					$tagContent = preg_replace('/\s+style(?=\s|$)/i', '', $tagContent);
					
					// Return cleaned content
					return '<' . $tagContent . '>';
				},
				$value
			);
		}
	}