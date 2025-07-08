<?php
	
	namespace Quellabs\Canvas\Validation\Foundation;
	
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;
	
	/**
	 * Validation rule that checks if at least one of the provided conditions is satisfied.
	 * This rule passes if any of the nested validation conditions returns true.
	 */
	abstract class RulesBase implements SanitizationRuleInterface {
		
		/**
		 * User provided error message
		 * @var string|null
		 */
		protected ?string $message = null;
		
		/**
		 * RulesBase constructor
		 * @param string|null $message
		 */
		public function __construct(?string $message=null) {
			$this->message = $message;
		}
		
		/**
		 * Replaces variables in an error string with their corresponding values.
		 * @param string $string The error string containing variables.
		 * @param array $variables An associative array of variable names and their values.
		 * @return string The error string with variables replaced.
		 */
		protected function replaceVariablesInErrorString(string $string, array $variables): string {
			return preg_replace_callback('/{{\\s*([a-zA-Z_][a-zA-Z0-9_]*)\\s*}}/', function ($matches) use ($variables) {
				return $variables[$matches[1]] ?? $matches[0];
			}, $string);
		}
	}