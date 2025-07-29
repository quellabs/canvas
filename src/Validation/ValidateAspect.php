<?php
	
	namespace Quellabs\Canvas\Validation;
	
	use Quellabs\Canvas\Validation\Contracts\ValidationInterface;
	use Quellabs\Canvas\Validation\Contracts\ValidationRuleInterface;
	use Quellabs\Contracts\AOP\BeforeAspect;
	use Quellabs\Contracts\AOP\MethodContext;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\JsonResponse;
	use Quellabs\Contracts\DependencyInjection\Container;
	
	/**
	 * Form validation aspect that intercepts method calls to validate request data
	 * before the method execution. Uses AOP (Aspect-Oriented Programming) pattern
	 * to separate validation concerns from business logic.
	 */
	class ValidateAspect implements BeforeAspect {
		
		/**
		 * @var Container The Dependency Injector container
		 */
		protected Container $di;
		
		/**
		 * @var string The fully qualified class name of the validation rules class
		 */
		protected string $validationClass;
		
		/**
		 * @var bool In the case of JSON, send an auto response. By default, this is disabled.
		 */
		protected bool $autoRespond;
		
		/**
		 * @var string|null The ID of the form being checked
		 */
		protected ?string $formId;
		
		/**
		 * ValidateFormAspect constructor
		 * @param Container $di The Dependency Injector object
		 * @param string $validator The validation class name that contains the rules
		 * @param bool $autoRespond In the case of JSON, send an auto response
		 */
		public function __construct(Container $di, string $validator, bool $autoRespond = false, ?string $formId = null) {
			$this->di = $di;
			$this->validationClass = $validator;
			$this->autoRespond = $autoRespond;
			$this->formId = $formId;
		}
		
		/**
		 * Executes before the target method is called
		 * Validates the request data and either returns an error response (for API calls)
		 * or sets validation attributes on the request (for web requests)
		 * @param MethodContext $context The method execution context containing request data
		 * @return Response|null Returns JsonResponse for failed API validations, null otherwise
		 */
		public function before(MethodContext $context): ?Response {
			// Extract the request from the method context
			// The context object wraps the incoming HTTP request and other execution data
			$request = $context->getRequest();

			// Skip validation if no form data is present
			if ($this->shouldSkipValidation($request)) {
				return null;
			}
			
			// Validate the class
			$validator = $this->createValidator();
			
			// Validate the request data against the defined rules
			// This calls a helper method that applies validation rules to the request data
			$errors = $this->validateRequest($request, $validator);
			
			// Prefix distinguishes validation results when multiple forms are present
			$prefix = $this->formId ? "{$this->formId}_" : '';
			
			// Handle validation failures
			if (!empty($errors)) {
				// For API requests, return JSON error immediately
				// Check if the request expects a JSON response (usually via Accept header or AJAX)
				if ($this->autoRespond && $this->expectsJson($request)) {
					// Return a structured JSON error response with HTTP 422 status
					// This immediately terminates the request lifecycle
					return $this->createValidationErrorResponse($errors);
				}
				
				// For web requests, set validation flags and let controller handle the response
				// Instead of returning immediately, we store the validation state in request attributes
				// This allows the controller to access validation results and render appropriate views
				$request->attributes->set("{$prefix}validation_passed", false);
				$request->attributes->set("{$prefix}validation_errors", $errors);
				return null;
			}
			
			// Validation passed - set success flags
			// Mark the data as valid so the controller knows validation succeeded
			$request->attributes->set("{$prefix}validation_passed", true);
			$request->attributes->set("{$prefix}validation_errors", []); // Empty array for consistency
			return null;
		}
		
		/**
		 * Creates the JSON error response for validation failures
		 * Override this method to customize the error response format
		 */
		protected function createValidationErrorResponse(array $errors): JsonResponse {
			return new JsonResponse([
				'message' => 'Validation failed',
				'errors'  => $errors
			], 422);
		}
		
		/**
		 * Creates and returns a validator instance.
		 * @return ValidationInterface The sanitizer instance
		 * @throws \InvalidArgumentException If sanitization class is invalid
		 * @throws \RuntimeException If sanitization class cannot be instantiated
		 */
		private function createValidator(): ValidationInterface {
			// Check if the specified class exists in the current namespace/autoloader
			// This prevents runtime errors when trying to instantiate non-existent classes
			if (!class_exists($this->validationClass)) {
				throw new \InvalidArgumentException("Validation class '{$this->validationClass}' does not exist");
			}
			
			// Verify that the class implements the ValidationInterface
			// This ensures the class has all required methods defined by the interface contract
			// Using is_subclass_of() to check interface implementation (works for both classes and interfaces)
			if (!is_subclass_of($this->validationClass, ValidationInterface::class)) {
				throw new \InvalidArgumentException("Validation class '{$this->validationClass}' must implement ValidationInterface");
			}
			
			try {
				// Instantiate the sanitization class to get the rules
				return $this->di->make($this->validationClass);
			} catch (\Throwable $e) {
				// If validation class instantiation fails, throw a more descriptive runtime exception
				throw new \RuntimeException("Failed to instantiate validation class '{$this->validationClass}': " . $e->getMessage(), 0, $e);
			}
		}
		
		/**
		 * Validates the input data against the given rules.
		 * Handles nested field structures recursively.
		 * @param Request $request The HTTP request containing form data
		 * @param ValidationInterface $rules The validation class containing the rules
		 * @return array Array of validation errors grouped by field name (preserving nested structure)
		 */
		private function validateRequest(Request $request, ValidationInterface $rules): array {
			// Initialize empty errors array to collect validation failures
			$errors = [];
			
			// Extract all form data from the request object
			// This includes POST data, file uploads, and other request parameters
			$requestData = $request->request->all();
			
			// Fetch content type
			$contentType = $request->headers->get('Content-Type', '');
			
			// Merge in JSON content if json is expected
			if ($this->isJsonContentType($contentType) && !empty($request->getContent())) {
				try {
					$jsonData = json_decode($request->getContent(), true, 512, JSON_THROW_ON_ERROR);
					
					if (is_array($jsonData)) {
						// Merge JSON data with form data (JSON takes precedence)
						$requestData = array_merge($requestData, $jsonData);
					}
				} catch (\JsonException $e) {
					// Invalid JSON - add a validation error
					$errors['_json'] = ['Invalid JSON data provided'];
					return $errors;
				}
			}
			
			// Recursively validate each field against its corresponding rules
			// This method handles both simple fields and nested array structures
			// Parameters:
			// - $rules->getRules(): Array of validation rules from the validation class
			// - $requestData: The actual data to validate
			// - $errors: Reference to errors array (modified by reference)
			// - $request: Original request object for context (e.g., file validation)
			$this->validateFields($rules->getRules(), $requestData, $errors, $request);
			
			// Return the collected errors array
			// Structure: ['field_name' => ['error1', 'error2'], 'nested.field' => ['error3']]
			return $errors;
		}
		
		/**
		 * Determines whether request validation should be skipped based on request method and data presence.
		 * @param Request $request The HTTP request object to evaluate
		 * @return bool True if validation should be skipped, false otherwise
		 */
		private function shouldSkipValidation(Request $request): bool {
			// Fetch request method
			$method = $request->getMethod();
			
			// Skip validation for safe methods (GET, HEAD, OPTIONS) with no query parameters
			if (in_array($method, ['GET', 'HEAD', 'OPTIONS']) && empty($request->query->all())) {
				return true;
			}
			
			// Skip validation for data-modifying requests with no data
			// Even POST/PUT/PATCH/DELETE requests might be sent without actual data
			// (e.g., a DELETE request that only uses the URL path parameter)
			if (in_array($request->getMethod(), ['POST', 'PUT', 'PATCH', 'DELETE'])) {
				// Check if request contains form data (application/x-www-form-urlencoded or multipart/form-data)
				$hasFormData = !empty($request->request->all());
				
				// Check if request contains uploaded files
				$hasFiles = !empty($request->files->all());
				
				// Check if request contains JSON data in the body
				// Check both that content exists and Content-Type indicates JSON
				$contentType = $request->headers->get('Content-Type', '');
				$hasJsonData = !empty($request->getContent()) && $this->isJsonContentType($contentType);
				$hasQueryData = !empty($request->query->all());
				
				// If none of the data types are present, skip validation
				// This covers cases like DELETE /api/users/123 where the ID is in the URL
				// and no additional data needs validation
				if (!$hasFormData && !$hasFiles && !$hasJsonData && !$hasQueryData) {
					return true;
				}
			}
			
			// Default to requiring validation for all other cases
			// This includes GET requests with query parameters and any data-modifying
			// requests that actually contain data to validate
			return false;
		}

		/**
		 * Determines if the request expects a JSON response
		 * Checks Accept header, Content-Type header, URL path patterns, and request format
		 * @param Request $request The HTTP request object
		 * @return bool True if JSON response is expected, false otherwise
		 */
		private function expectsJson(Request $request): bool {
			// Check if the request format is explicitly set to JSON
			if ($request->getRequestFormat() === 'json') {
				return true;
			}
			
			// Check Accept header for JSON content types
			$acceptHeader = $request->headers->get('Accept', '');
			$contentType = $request->headers->get('Content-Type', '');
			
			// Check Content-Type header for JSON content types
			if ($this->isJsonContentType($contentType)) {
				return true;
			}
			
			// Check Accept header
			if ($this->acceptsJsonContentType($acceptHeader)) {
				return true;
			}
			
			// Check URL patterns
			if ($this->isApiPath($request->getPathInfo())) {
				return true;
			}
			
			// Check AJAX call
			if ($request->isXmlHttpRequest()) {
				return str_contains($acceptHeader, 'application/json');
			}
			
			// We do not except JSON
			return false;
		}
		
		/**
		 * Checks if the Accept header indicates JSON is acceptable
		 * @param string $acceptHeader The Accept header value
		 * @return bool True if JSON content types are accepted
		 */
		private function acceptsJsonContentType(string $acceptHeader): bool {
			$jsonTypes = [
				'application/json',
				'application/vnd.api+json',
				'application/hal+json',
				'application/ld+json',
				'application/problem+json',
				'text/json'
			];
			
			foreach ($jsonTypes as $type) {
				if (str_contains($acceptHeader, $type)) {
					return true;
				}
			}
			
			return false;
		}
		
		/**
		 * Checks if the Content-Type header indicates JSON content
		 * @param string $contentType The Content-Type header value
		 * @return bool True if it's a JSON content type
		 */
		private function isJsonContentType(string $contentType): bool {
			// Remove charset and other parameters
			$contentType = strtok($contentType, ';');
			
			$jsonTypes = [
				'application/json',
				'application/vnd.api+json',
				'application/hal+json',
				'application/ld+json',
				'application/problem+json',
				'text/json'
			];
			
			return in_array(trim($contentType), $jsonTypes, true);
		}
		
		/**
		 * Checks if the URL path indicates an API endpoint
		 * @param string $pathInfo The request path
		 * @return bool True if it looks like an API path
		 */
		private function isApiPath(string $pathInfo): bool {
			$apiPatterns = [
				'/^\/api\//',           // /api/...
				'/^\/v\d+\//',          // /v1/, /v2/, etc.
				'/^\/api\/v\d+\//',     // /api/v1/, /api/v2/, etc.
				'/\.json$/',            // ends with .json
				'/^\/graphql/',         // GraphQL endpoints
				'/^\/webhook/',         // Webhook endpoints
			];
			
			foreach ($apiPatterns as $pattern) {
				if (preg_match($pattern, $pathInfo)) {
					return true;
				}
			}
			
			return false;
		}
		
		/**
		 * Recursively validates fields, handling nested field structures
		 * Fixed version that creates flattened error keys using dot notation
		 * @param array $rules The validation rules (can be nested)
		 * @param array $data The data to validate (can be nested)
		 * @param array &$errors Reference to the errors array to populate (uses flattened keys)
		 * @param Request $request The HTTP request object
		 * @param string $prefix Current field path prefix for building dot notation keys
		 */
		private function validateFields(array $rules, array $data, array &$errors, Request $request, string $prefix = ''): void {
			// Loop through each field in the validation rules
			foreach ($rules as $fieldName => $validators) {
				// Build the full field name using dot notation
				// For nested fields like customer.name, this creates the complete path
				$fullFieldName = $prefix ? "{$prefix}.{$fieldName}" : $fieldName;
				
				// Get the field value from the current data level
				// Uses null coalescing to handle missing fields gracefully
				$fieldValue = $data[$fieldName] ?? null;
				
				// Check if this is a nested field structure (validators is an associative array of field names)
				// vs a field with actual validators (array of validator objects)
				if (!$this->isNestedFieldStructure($validators)) {
					// This is a field with actual validators, validate it directly
					$fieldErrors = $this->validateSingleField($fullFieldName, $fieldValue, $validators, $request);
					
					// Add any errors found for this field using the flattened key
					// This ensures consistent error structure: ['customer.name' => ['error'], 'address' => ['error']]
					if (!empty($fieldErrors)) {
						$errors[$fullFieldName] = $fieldErrors; // Flattened key instead of nested array
					}
					
					// Move to the next field
					continue;
				}
				
				// Recursively validate the nested fields
				// Pass the current full field name as the new prefix to build proper dot notation
				// e.g., if we're validating 'customer' and now validating 'name', prefix becomes 'customer'
				$nestedData = is_array($fieldValue) ? $fieldValue : [];
				$this->validateFields($validators, $nestedData, $errors, $request, $fullFieldName);
			}
		}
		
		/**
		 * Determines if an array represents a nested field structure or a list of validators
		 * @param array $validators The array to check
		 * @return bool True if it's a nested field structure, false if it's validators
		 */
		private function isNestedFieldStructure(array $validators): bool {
			// Empty arrays are treated as validator arrays (safer default)
			if (empty($validators)) {
				return false;
			}
			
			// Strategy: Look for ANY ValidationInterface objects in the structure
			// If we find any, it's a validator array. If we find none, it's nested fields.
			foreach ($validators as $value) {
				// Case 1: Direct validator object
				// Example: ['email' => EmailValidator]
				if ($value instanceof ValidationRuleInterface) {
					return false; // Found a validator, so this is a validator array
				}
				
				// Case 2: Array that might contain validators
				// Example: ['email' => [EmailValidator, RequiredValidator]]
				if (is_array($value)) {
					// Check each item in the sub-array
					foreach ($value as $item) {
						if ($item instanceof ValidationRuleInterface) {
							return false; // Found a validator in sub-array, so this is a validator array
						}
					}
				}
				
				// Case 3: Other types (strings, objects, etc.) are ignored
				// They don't help us determine the structure type
			}
			
			// No ValidationInterface objects found anywhere in the structure
			// This means it's a nested field structure containing only field definitions
			return true;
		}
		
		/**
		 * Validates a single field against its validators
		 * @param string $fieldName The name of the field being validated
		 * @param mixed $fieldValue The value of the field from the request
		 * @param mixed $validators The validator(s) for this field
		 * @param Request $request The HTTP request object
		 * @return array Array of validation errors for this field
		 */
		private function validateSingleField(string $fieldName, $fieldValue, $validators, Request $request): array {
			$errors = [];
			
			// Normalize validators to array format for consistent processing
			$validators = is_array($validators) ? $validators : [$validators];
			
			// Apply each validator to the current field
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
					if (!$validator->validate($fieldValue, $request)) {
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
			// Use regex to find and replace {{variable}} patterns
			return preg_replace_callback('/{{\s*([a-zA-Z_]\w*)\s*}}/', function ($matches) use ($variables) {
				// Replace it with actual value if exists, otherwise keep the original placeholder
				return $variables[$matches[1]] ?? $matches[0];
			}, $string);
		}
	}