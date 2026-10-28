<?php
	
	namespace Quellabs\Canvas\Validation;
	
	use Quellabs\Canvas\Exceptions\ValidationException;
	use Quellabs\Canvas\Validation\Contracts\ValidationInterface;
	use Quellabs\Canvas\AOP\Contracts\BeforeAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Quellabs\Contracts\DependencyInjection\ContainerInterface;

	/**
	 * Form validation aspect that intercepts method calls to validate request data
	 * before the method execution. Uses AOP (Aspect-Oriented Programming) pattern
	 * to separate validation concerns from business logic.
	 *
	 * Failure modes:
	 * - Default (throwOnFailure = false): writes validation_passed/validation_errors
	 *   to the request attributes, then continues. The controller is responsible for
	 *   checking these attributes and deciding how to respond.
	 * - throwOnFailure = true: throws ValidationException, which the framework's
	 *   exception handler converts into an HTTP response. Use this when you want
	 *   centralized, uniform error handling and do not need per-controller logic.
	 */
	class ValidateAspect implements BeforeAspectInterface {

		/**
		 * @var ContainerInterface The Dependency Injector container
		 */
		protected ContainerInterface $di;

		/**
		 * @var string The fully qualified class name of the validation rules class
		 */
		protected string $validationClass;

		/**
		 * @var string|null The ID of the form being checked
		 */
		protected ?string $formId;

		/**
		 * @var bool If true, throws ValidationException on failure instead of
		 * only writing to request attributes
		 */
		protected bool $throwOnFailure;

		/**
		 * @var Validator The validator instance
		 */
		protected Validator $validator;

		/**
		 * ValidateFormAspect constructor
		 * @param ContainerInterface $di The Dependency Injector object
		 * @param string $validator The validation class name that contains the rules
		 * @param string|null $formId Optional form ID for multi-form scenarios
		 * @param bool $throwOnFailure If true, throws ValidationException on failure in
		 *                             addition to writing failure info to request attributes
		 */
		public function __construct(ContainerInterface $di, string $validator, ?string $formId = null, bool $throwOnFailure = false) {
			$this->di = $di;
			$this->validationClass = $validator;
			$this->formId = $formId;
			$this->throwOnFailure = $throwOnFailure;
			$this->validator = new Validator();
		}

		/**
		 * Executes before the target method is called
		 * Validates the request data and sets validation_passed/validation_errors
		 * request attributes for the controller to act on. Throws ValidationException
		 * instead when throwOnFailure is enabled and validation fails; a misconfigured
		 * validator class always throws, regardless of throwOnFailure.
		 * @param MethodContextInterface $context The method execution context containing request data
		 * @return Response|null Always null; throws ValidationException if throwOnFailure is
		 *                        enabled and validation fails
		 * @throws ValidationException If throwOnFailure is true and the data fails validation
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

			// Always write results to request attributes — controllers and exception
			// handlers both benefit from having them available without re-validating
			$request->attributes->set("{$prefix}validation_passed", empty($errors));
			$request->attributes->set("{$prefix}validation_errors", $errors);

			// Validation failed — throw if opted in, otherwise continue to controller
			if (!empty($errors) && $this->throwOnFailure) {
				throw new ValidationException('Validation failed', $errors, $this->formId);
			}

			return null;
		}
		
		/**
		 * Extracts only $_POST and $_GET data from the request.
		 * Does NOT handle JSON request bodies.
		 * @param Request $request The HTTP request
		 * @return array<string, mixed> The merged POST and GET data (POST takes precedence)
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
	}
