<?php
	
	namespace Quellabs\Canvas\Validation;
	
	use Quellabs\Canvas\Validation\Contracts\ValidationInterface;
	use Quellabs\Canvas\Validation\Contracts\ValidationRuleInterface;
	
	/**
	 * Standalone validator that validates data arrays against validation rules.
	 * Can be used independently without the AOP aspect.
	 */
	class Validator {
		
		/**
		 * Validates data against the given validation rules.
		 * @param array $data The data to validate
		 * @param ValidationInterface $rules The validation rules
		 * @return array Array of validation errors grouped by field name (using dot notation for nested fields)
		 */
		public function validate(array $data, ValidationInterface $rules): array {
			$errors = [];
			$this->validateFields($rules->getRules(), $data, $errors);
			return $errors;
		}
		
		/**
		 * Recursively validates fields, handling nested field structures
		 * @param array $rules The validation rules (can be nested)
		 * @param array $data The data to validate (can be nested)
		 * @param array &$errors Reference to the errors array to populate (uses flattened keys with dot notation)
		 * @param string $prefix Current field path prefix for building dot notation keys
		 */
		private function validateFields(array $rules, array $data, array &$errors, string $prefix = ''): void {
			foreach ($rules as $fieldName => $validators) {
				// Build the full field name using dot notation
				$fullFieldName = $prefix ? "{$prefix}.{$fieldName}" : $fieldName;
				
				// Get the field value from the current data level
				$fieldValue = $data[$fieldName] ?? null;
				
				// Check if this is a nested field structure vs a field with actual validators
				if (!$this->isNestedFieldStructure($validators)) {
					// This is a field with actual validators, validate it directly
					$fieldErrors = $this->validateSingleField($fullFieldName, $fieldValue, $validators);
					
					// Add any errors found for this field using the flattened key
					if (!empty($fieldErrors)) {
						$errors[$fullFieldName] = $fieldErrors;
					}
					
					continue;
				}
				
				// Recursively validate the nested fields
				$nestedData = is_array($fieldValue) ? $fieldValue : [];
				$this->validateFields($validators, $nestedData, $errors, $fullFieldName);
			}
		}
		
		/**
		 * Determines if an array represents a nested field structure or a list of validators
		 * @param array $validators The array to check
		 * @return bool True if it's a nested field structure, false if it's validators
		 */
		private function isNestedFieldStructure(array $validators): bool {
			if (empty($validators)) {
				return false;
			}
			
			// Look for ANY ValidationRuleInterface objects in the structure
			// If we find any, it's a validator array. If we find none, it's nested fields.
			foreach ($validators as $value) {
				// Case 1: Direct validator object
				if ($value instanceof ValidationRuleInterface) {
					return false;
				}
				
				// Case 2: Array that might contain validators
				if (is_array($value)) {
					foreach ($value as $item) {
						if ($item instanceof ValidationRuleInterface) {
							return false;
						}
					}
				}
			}
			
			// No ValidationRuleInterface objects found - it's a nested field structure
			return true;
		}
		
		/**
		 * Validates a single field against its validators
		 * @param string $fieldName The name of the field being validated
		 * @param mixed $fieldValue The value of the field
		 * @param mixed $validators The validator(s) for this field
		 * @return array Array of validation errors for this field
		 */
		private function validateSingleField(string $fieldName, $fieldValue, $validators): array {
			$errors = [];
			
			// Normalize validators to array format
			$validators = is_array($validators) ? $validators : [$validators];
			
			foreach ($validators as $validator) {
				// Validate that the validator implements ValidationRuleInterface
				if (!$validator instanceof ValidationRuleInterface) {
					$type = is_object($validator) ? get_class($validator) : gettype($validator);
					throw new \InvalidArgumentException(
						"Invalid validator for field '{$fieldName}'. Expected ValidationRuleInterface, got {$type}"
					);
				}
				
				// Run the validation check
				try {
					if (!$validator->validate($fieldValue)) {
						$errors[] = $this->replaceVariablesInErrorString(
							$validator->getError(),
							[
								'key'   => $fieldName,
								'value' => $fieldValue,
							]
						);
					}
				} catch (\Throwable $e) {
					$validatorClass = get_class($validator);
					throw new \RuntimeException(
						"Validator {$validatorClass} failed for field '{$fieldName}': {$e->getMessage()}",
						0,
						$e
					);
				}
			}
			
			return $errors;
		}
		
		/**
		 * Replaces template variables in error messages with actual values
		 * Uses {{variable_name}} syntax for variable placeholders
		 * @param string $string The error string containing variable placeholders
		 * @param array $variables Associative array of variable names and their values
		 * @return string The error string with variables replaced by actual values
		 */
		private function replaceVariablesInErrorString(string $string, array $variables): string {
			return preg_replace_callback('/{{\s*([a-zA-Z_]\w*)\s*}}/', function ($matches) use ($variables) {
				return $variables[$matches[1]] ?? $matches[0];
			}, $string);
		}
	}