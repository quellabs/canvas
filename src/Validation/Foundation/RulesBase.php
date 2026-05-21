<?php
	
	namespace Quellabs\Canvas\Validation\Foundation;
	
	use Quellabs\Canvas\Validation\Contracts\ValidationRuleInterface;
	
	/**
	 * Validation rule that checks if at least one of the provided conditions is satisfied.
	 * This rule passes if any of the nested validation conditions returns true.
	 */
	abstract class RulesBase implements ValidationRuleInterface {
		
		/**
		 * User provided error message
		 * @var string|null
		 */
		protected ?string $message = null;
		
		/**
		 * RulesBase constructor
		 * @param string|null $message
		 */
		public function __construct(?string $message = null) {
			$this->message = $message;
		}
		
		/**
		 * Replaces variables in an error string with their corresponding values.
		 * @param string $string The error string containing variables.
		 * @param array<string, mixed> $variables An associative array of variable names and their values.
		 * @return string The error string with variables replaced.
		 */
		protected function replaceVariablesInErrorString(string $string, array $variables): string {
			return preg_replace_callback(
				// Match placeholders like {{ field_name }}
				'/{{\s*([a-zA-Z_]\w*)\s*}}/',
				function (array $matches) use ($variables): string {
					// Extract the placeholder key captured by the regex
					$key = $matches[1];
					
					// If no replacement value exists, keep the original placeholder
					if (!array_key_exists($key, $variables)) {
						return $matches[0];
					}
					
					// Only scalar values can be safely converted to string
					// (string, int, float, bool). Otherwise, keep the placeholder.
					if (is_scalar($variables[$key])) {
						return (string)$variables[$key];
					} else {
						return $matches[0];
					}
				},
				$string
			) ?? $string;
		}
	}