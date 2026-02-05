<?php
	
	namespace Quellabs\Canvas\Validation;
	
	use Quellabs\Canvas\Validation\Contracts\ValidationInterface;
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\JsonResponse;
	use Quellabs\Contracts\DependencyInjection\Container;
	
	/**
	 * Form validation aspect that intercepts method calls to validate request data
	 * before the method execution. Uses AOP (Aspect-Oriented Programming) pattern
	 * to separate validation concerns from business logic.
	 */
	class ValidateAspect implements BeforeAspectInterface {
		
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
		 * @var Validator The validator instance
		 */
		protected Validator $validator;
		
		/**
		 * ValidateFormAspect constructor
		 * @param Container $di The Dependency Injector object
		 * @param string $validator The validation class name that contains the rules
		 * @param bool $autoRespond In the case of JSON, send an auto response
		 * @param string|null $formId Optional form ID for multi-form scenarios
		 */
		public function __construct(Container $di, string $validator, bool $autoRespond = false, ?string $formId = null) {
			$this->di = $di;
			$this->validationClass = $validator;
			$this->autoRespond = $autoRespond;
			$this->formId = $formId;
			$this->validator = new Validator();
		}
		
		/**
		 * Executes before the target method is called
		 * Validates the request data and either returns an error response (for API calls)
		 * or sets validation attributes on the request (for web requests)
		 * @param MethodContextInterface $context The method execution context containing request data
		 * @return Response|null Returns JsonResponse for failed API validations, null otherwise
		 */
		public function before(MethodContextInterface $context): ?Response {
			$request = $context->getRequest();
			
			// Skip validation if no form data is present
			if (!$this->shouldPerformValidation($request)) {
				return null;
			}
			
			// Create the validation rules instance
			$rules = $this->createValidationRules();
			
			// Extract only $_POST and $_GET data (no JSON body handling)
			$requestData = $this->extractRequestData($request);
			
			// Validate the data using the Validator
			$errors = $this->validator->validate($requestData, $rules);
			
			// Prefix distinguishes validation results when multiple forms are present
			$prefix = $this->formId ? "{$this->formId}_" : '';
			
			// Handle validation failures
			if (!empty($errors)) {
				// For API requests, return JSON error immediately
				if ($this->autoRespond && $this->expectsJson($request)) {
					return $this->createValidationErrorResponse($errors);
				}
				
				// For web requests, set validation flags and let controller handle the response
				$request->attributes->set("{$prefix}validation_passed", false);
				$request->attributes->set("{$prefix}validation_errors", $errors);
				return null;
			}
			
			// Validation passed - set success flags
			$request->attributes->set("{$prefix}validation_passed", true);
			$request->attributes->set("{$prefix}validation_errors", []);
			return null;
		}
		
		/**
		 * Extracts only $_POST and $_GET data from the request.
		 * Does NOT handle JSON request bodies.
		 * @param Request $request The HTTP request
		 * @return array The merged POST and GET data (POST takes precedence)
		 */
		protected function extractRequestData(Request $request): array {
			// Get POST data ($_POST)
			$postData = $request->request->all();
			
			// Get GET data ($_GET)
			$getData = $request->query->all();
			
			// Merge with POST taking precedence
			return array_merge($getData, $postData);
		}
		
		/**
		 * Creates the JSON error response for validation failures
		 * Override this method to customize the error response format
		 * @param array $errors
		 * @return JsonResponse
		 */
		protected function createValidationErrorResponse(array $errors): JsonResponse {
			return new JsonResponse([
				'message' => 'Validation failed',
				'errors'  => $errors
			], 422);
		}
		
		/**
		 * Creates and returns a validation rules instance.
		 * @return ValidationInterface The validation rules instance
		 * @throws \InvalidArgumentException If validation class is invalid
		 * @throws \RuntimeException If validation class cannot be instantiated
		 */
		private function createValidationRules(): ValidationInterface {
			if (!class_exists($this->validationClass)) {
				throw new \InvalidArgumentException("Validation class '{$this->validationClass}' does not exist");
			}
			
			if (!is_subclass_of($this->validationClass, ValidationInterface::class)) {
				throw new \InvalidArgumentException("Validation class '{$this->validationClass}' must implement ValidationInterface");
			}
			
			try {
				return $this->di->make($this->validationClass);
			} catch (\Throwable $e) {
				throw new \RuntimeException("Failed to instantiate validation class '{$this->validationClass}': " . $e->getMessage(), 0, $e);
			}
		}
		
		/**
		 * Determines whether request validation should be performed based on request method and data presence.
		 * @param Request $request The HTTP request to check
		 * @return bool True if validation should be performed, false otherwise
		 */
		private function shouldPerformValidation(Request $request): bool {
			// Only validate POST, PUT, PATCH, or DELETE requests
			// These are the methods that typically submit form data
			$method = strtoupper($request->getMethod());
			if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
				return false;
			}
			
			// Only validate if there's POST or GET data
			if (empty($request->request->all()) && empty($request->query->all())) {
				return false;
			}
			
			return true;
		}
		
		/**
		 * Determines if the request expects a JSON response
		 * Checks multiple indicators including Accept header, AJAX, and URL patterns
		 * @param Request $request The HTTP request
		 * @return bool True if JSON response is expected
		 */
		private function expectsJson(Request $request): bool {
			// Check if request explicitly wants JSON via Accept header
			if ($request->getPreferredFormat() === 'json') {
				return true;
			}
			
			// Check if it's an AJAX request wanting JSON
			if ($request->isXmlHttpRequest()) {
				$acceptHeader = $request->headers->get('Accept', '');
				if (str_contains($acceptHeader, 'application/json')) {
					return true;
				}
			}
			
			// Check if the URL path indicates an API endpoint
			if ($this->isApiPath($request->getPathInfo())) {
				return true;
			}
			
			return false;
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
	}