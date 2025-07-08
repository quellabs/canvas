<?php
	
	namespace Quellabs\Canvas\Sanitization;
	
	use Quellabs\Canvas\Validation\Contracts\ValidationInterface;
	use Quellabs\Contracts\AOP\BeforeAspect;
	use Quellabs\Canvas\Sanitization\Contracts\SanitizationInterface;
	use Quellabs\Contracts\AOP\MethodContext;
	use Quellabs\Contracts\DependencyInjection\Container;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Aspect-Oriented Programming (AOP) class that sanitizes HTTP request data
	 * before method execution. This aspect can be applied to controller methods
	 * to automatically sanitize incoming POST and GET data.
	 */
	class SanitizeAspect implements BeforeAspect {
		
		/**
		 * @var Container The Dependency Injector container
		 */
		protected Container $di;
		
		/**
		 * The fully qualified class name of the sanitization class to use.
		 * If null, no sanitization will be performed.
		 * @var string|null
		 */
		private ?string $sanitizationClass;
		
		/**
		 * Constructor to initialize the sanitization class.
		 * @param string|null $sanitizer The fully qualified class name of the sanitization class
		 */
		public function __construct(Container $di, ?string $sanitizer = null) {
			$this->di = $di;
			$this->sanitizationClass = $sanitizer;
		}
		
		/**
		 * Before aspect method that executes before the target method.
		 * Sanitizes both POST and GET request data based on the configured sanitization rules.
		 * @param MethodContext $context The method execution context containing request data
		 * @return Response|null Returns null to continue execution, or a Response to short-circuit
		 */
		public function before(MethodContext $context): ?Response {
			// Skip sanitization if no sanitizer is configured
			if (!$this->sanitizationClass) {
				return null;
			}
			
			// Get the sanitizer instance and rules
			$sanitizer = $this->createSanitizer();
			$rules = $sanitizer->getRules();
			
			// Sanitize the request data
			$this->sanitizeRequestData($context->getRequest(), $rules);
			
			// Return null to continue with normal method execution
			return null;
		}
		
		/**
		 * Creates and returns a sanitizer instance.
		 * @return SanitizationInterface The sanitizer instance
		 * @throws \InvalidArgumentException If sanitization class is invalid
		 * @throws \RuntimeException If sanitization class cannot be instantiated
		 */
		private function createSanitizer(): SanitizationInterface {
			// Check if the specified class exists in the current namespace/autoloader
			// This prevents runtime errors when trying to instantiate non-existent classes
			if (!class_exists($this->sanitizationClass)) {
				throw new \InvalidArgumentException("Sanitization class '{$this->sanitizationClass}' does not exist");
			}
			
			// Verify that the class implements the SanitizationInterface
			// This ensures the class has all required methods defined by the interface contract
			// Using is_subclass_of() to check interface implementation (works for both classes and interfaces)
			if (!is_subclass_of($this->sanitizationClass, SanitizationInterface::class)) {
				throw new \InvalidArgumentException("Sanitization class '{$this->sanitizationClass}' must implement SanitizationInterface");
			}
			
			try {
				// Instantiate the sanitization class to get the rules
				return $this->di->make($this->sanitizationClass);
			} catch (\Throwable $e) {
				// If validation class instantiation fails, throw a more descriptive runtime exception
				throw new \RuntimeException("Failed to instantiate sanitization class '{$this->sanitizationClass}': " . $e->getMessage(), 0, $e);
			}
		}
		
		/**
		 * Sanitizes the request data (both POST and GET) using the provided rules.
		 * @param Request $request The HTTP request to sanitize
		 * @param array $rules The sanitization rules
		 */
		private function sanitizeRequestData(Request $request, array $rules): void {
			// Sanitize POST data and replace the original request data
			$post = $request->request->all();
			$request->request->replace($this->applySanitization($post, $rules));
			
			// Sanitize GET data and replace the original query parameters
			$query = $request->query->all();
			$request->query->replace($this->applySanitization($query, $rules));
		}
		
		/**
		 * Recursively applies sanitization rules to an array of data.
		 * Handles nested arrays and applies specific sanitization rules based on field names.
		 * @param array $data The data array to sanitize
		 * @param array $rules The sanitization rules mapping field names to sanitizer arrays
		 * @return array The sanitized data array
		 */
		private function applySanitization(array $data, array $rules): array {
			foreach ($data as $key => $value) {
				// Recursively sanitize nested arrays
				if (is_array($value)) {
					$data[$key] = $this->applySanitization($value, $rules);
					continue;
				}
				
				// Apply sanitization rules if they exist for this field
				if (isset($rules[$key])) {
					$data[$key] = $this->sanitizeValue($value, $rules[$key]);
				}
				
				// Fields without rules are left unchanged
			}
			
			return $data;
		}
		
		/**
		 * Applies a chain of sanitizers to a single value.
		 * Each sanitizer in the array is applied sequentially to the value.
		 * @param mixed $value The value to sanitize
		 * @param array $sanitizers Array of sanitizer objects that implement a sanitize() method
		 * @return mixed The sanitized value after all sanitizers have been applied
		 */
		private function sanitizeValue(mixed $value, array $sanitizers): mixed {
			// Apply each sanitizer in sequence
			foreach ($sanitizers as $sanitizer) {
				$value = $sanitizer->sanitize($value);
			}
			
			return $value;
		}
	}