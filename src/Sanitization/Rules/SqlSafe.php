<?php
	
	namespace Quellabs\Canvas\Sanitization\Rules;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * Removes potentially dangerous SQL injection patterns from input strings.
	 * This rule helps prevent SQL injection attacks by sanitizing user input
	 * before it's processed or stored.
	 */
	class SqlSafe implements SanitizationRuleInterface {

		/**
		 * Array of regex patterns that match potentially dangerous SQL constructs
		 * @var array<string> Regular expressions to identify and remove SQL injection patterns
		 */
		private array $dangerousPatterns = [
			'/--.*$/m',           // SQL single-line comments (-- comment)
			'/\/\*.*?\*\//s',     // SQL multi-line comments (/* comment */)
			'/;\s*$/m',           // Trailing semicolons that could terminate statements
			'/\b(xp_|sp_)\w+/i',  // SQL Server extended procedures (xp_) and stored procedures (sp_)
			'/\b(union|select|insert|update|delete|drop|create|alter)\s+/i' // Common SQL keywords that could be used in injection attacks
		];
		
		/**
		 * Sanitize the input value by removing dangerous SQL patterns
		 * @param mixed $value The input value to sanitize
		 * @return mixed The sanitized value (unchanged if not a string)
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - other types are returned unchanged
			if (!is_string($value)) {
				return $value;
			}
			
			// Apply each dangerous pattern regex to remove potential SQL injection attempts
			foreach ($this->dangerousPatterns as $pattern) {
				$value = preg_replace($pattern, '', $value);
			}
			
			// Return the sanitized string
			return $value;
		}
	}