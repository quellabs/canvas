<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * This class implements a sanitization rule that removes HTML and XML tags
	 * from string values, with optional support for preserving specific allowed tags.
	 * Non-string values are returned unchanged.
	 */
	class StripTags implements SanitizationRuleInterface {
		
		/**
		 * @var array Array of HTML tag names that should be preserved
		 */
		private array $allowedTags;
		
		/**
		 * Constructor for StripTags sanitization rule.
		 * @param array $allowedTags Array of HTML tag names that should be preserved
		 */
		public function __construct(array $allowedTags = []) {
			$this->allowedTags = $allowedTags;
		}
		
		/**
		 * Sanitize the given value by removing HTML/XML tags.
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value (string with tags removed, or original value if not a string)
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - other types are returned as-is
			if (!is_string($value)) {
				return $value;
			}
			
			// If no allowed tags specified, strip all tags
			if (empty($this->allowedTags)) {
				return strip_tags($value);
			}
			
			// Build allowed tags string in format required by strip_tags()
			// Converts ['p', 'br'] to '<p><br>'
			return strip_tags($value, $this->transformAllowedTags($this->allowedTags));
		}
		
		/**
		 * Build allowed tags string in format required by strip_tags()
		 * Converts ['p', 'br'] to '<p><br>'
		 * @param array $tags
		 * @return string
		 */
		private function transformAllowedTags(array $tags): string {
			return '<' . implode('><', $tags) . '>';
		}
	}