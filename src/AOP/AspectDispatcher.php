<?php
	
	namespace Quellabs\Canvas\AOP;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Contracts\AOP\AfterAspect;
	use Quellabs\Contracts\AOP\AroundAspect;
	use Quellabs\Contracts\AOP\BeforeAspect;
	use Quellabs\Contracts\AOP\RequestAspect;
	use Quellabs\DependencyInjection\Container;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	class AspectDispatcher {
		
		private AnnotationReader $annotationReader;
		private Container $di;
		
		/**
		 * AspectDispatcher constructor
		 * @param AnnotationReader $annotationReader
		 * @param Container $di
		 */
		public function __construct(AnnotationReader $annotationReader, Container $di) {
			$this->annotationReader = $annotationReader;
			$this->di = $di;
		}
		
		/**
		 * Orchestrates the complete AOP-enabled execution of a controller method
		 *
		 * This is the main entry point for aspect-oriented programming execution.
		 * It coordinates the entire aspect pipeline, executing aspects in the proper order:
		 * Request → Before → Around → After, with proper exception handling for
		 * early termination scenarios.
		 *
		 * Execution Flow:
		 * 1. Creates method context with reflection data and annotations
		 * 2. Resolves and instantiates all applicable aspects
		 * 3. Executes request transformation aspects
		 * 4. Executes before aspects (can short-circuit)
		 * 5. Executes the controller method wrapped by around aspects
		 * 6. Executes after aspects for response post-processing
		 * 7. Returns the final response
		 *
		 * @param Request $request The incoming HTTP request object
		 * @param object $controller The controller instance containing the target method
		 * @param string $method The name of the method to execute on the controller
		 * @param array $arguments Method arguments resolved from route parameters
		 * @return Response The final HTTP response after all aspect processing
		 * @throws \ReflectionException When method reflection fails
		 */
		public function dispatch(Request $request, object $controller, string $method, array $arguments): Response {
			try {
				// Create a comprehensive method context containing all execution metadata
				// This context object is passed to all aspects for introspection
				$context = new MethodContext(
					request: $request,
					target: $controller,
					methodName: $method,
					arguments: $arguments,
					reflection: new \ReflectionMethod($controller, $method)
				);
				
				// Discover and instantiate all aspects that apply to this method
				// Uses annotation scanning and dependency injection for aspect creation
				$aspects = $this->getResolvedAspects($controller, $method);
				
				// Phase 1: Transform the incoming request.
				// Request aspects can modify headers, parameters, or add computed attributes
				$this->handleRequestAspects($aspects, $request);
				
				// Phase 2: Execute pre-execution logic
				// Before aspects can perform authorization, validation, or early returns
				$this->handleBeforeAspects($aspects, $context);
				
				// Phase 3: Execute the controller method with interception
				// Around aspects can modify execution, add caching, or replace method entirely
				$result = $this->handleAroundAspects($controller, $method, $aspects, $context);
				
				// Phase 4: Post-process the response
				// After aspects can add headers, cookies, logging, or response transformations
				$this->handleAfterAspects($aspects, $context, $result);
				
				// Return the final response after all aspect processing
				return $result;
			} catch (AopException $e) {
				// Handle early termination from before aspects or other flow control
				// AopException carries the response that should be returned immediately
				return $e->getResponse();
			}
		}
		
		/**
		 * Resolves and instantiates aspects for a given controller method.
		 * @param object $controller The controller instance that contains the target method
		 * @param string $method The name of the method to resolve aspects for
		 * @return array Array of instantiated aspect objects ready for execution
		 */
		private function getResolvedAspects(object $controller, string $method): array {
			// Instantiate AspectResolver, which is used to find AOP classes
			$aspectResolver = new AspectResolver($this->annotationReader);
			
			// Use the aspect resolver to determine which aspects apply to this controller method
			// Returns an array where keys are aspect class names and values are constructor parameters
			$aspects = $aspectResolver->resolve($controller, $method);
			
			// Iterate through each resolved aspect and instantiate it
			$aspectsResolved = [];

			foreach($aspects as $entry) {
				// Use dependency injection container to create aspect instance with its parameters
				// The DI container handles constructor injection and aspect lifecycle
				$aspectsResolved[] = $this->di->make($entry['class'], $entry['parameters']);
			}
			
			return $aspectsResolved;
		}
		
		/**
		 * Execute request transformation aspects on the incoming HTTP request
		 * @param array $aspects Array of aspect instances to process
		 * @param Request $request The Symfony Request object to transform
		 * @return void
		 */
		private function handleRequestAspects(array $aspects, Request $request): void {
			foreach ($aspects as $aspect) {
				if ($aspect instanceof RequestAspect) {
					// Transform the request object in-place
					$aspect->transformRequest($request);
				}
			}
		}
		
		/**
		 * Execute before aspects prior to controller method execution
		 * @param array $aspects Array of aspect instances to process
		 * @param MethodContext $context Context object containing method metadata and parameters
		 * @return void
		 * @throws AopException When an aspect returns a Response object to short-circuit execution
		 */
		private function handleBeforeAspects(array $aspects, MethodContext $context): void {
			foreach ($aspects as $aspect) {
				if ($aspect instanceof BeforeAspect) {
					// Execute the before logic and check for early response
					$response = $aspect->before($context);
					
					// If the aspect returns a response, halt execution and throw it
					if ($response !== null) {
						throw new AopException($response);
					}
				}
			}
		}
		
		/**
		 * Execute after aspects following controller method execution
		 * @param array $aspects Array of aspect instances to process
		 * @param MethodContext $context Context object containing method metadata and parameters
		 * @param Response|null $response The response object from the controller method to be modified
		 * @return void
		 */
		private function handleAfterAspects(array $aspects, MethodContext $context, ?Response $response): void {
			if ($response !== null) {
				foreach ($aspects as $aspect) {
					if ($aspect instanceof AfterAspect) {
						// After aspects modify the response object directly.
						// No return value expected - modifications happen in-place
						$aspect->after($context, $response);
					}
				}
			}
		}
		
		/**
		 * Executes the controller method wrapped by around aspects in a nested chain
		 * Around aspects can intercept, modify, or completely replace method execution
		 * @param object $controller The controller instance
		 * @param string $method The method name to execute
		 * @param array $aspects All resolved aspects for this method
		 * @param MethodContext $context Context information about the method call
		 * @return mixed The result from the method or final around aspect
		 */
		private function handleAroundAspects(object $controller, string $method, array $aspects, MethodContext $context): mixed {
			// Filter to get only around aspects from all resolved aspects
			$aroundAspects = array_filter($aspects, fn($aspect) => $aspect instanceof AroundAspect);
			
			// If no around aspects exist, execute the method directly without interception
			if (empty($aroundAspects)) {
				return $this->di->invoke($controller, $method, $context->getArguments());
			}
			
			// Create the base "proceed" function that calls the actual controller method
			// This is the innermost function in the chain
			$proceed = fn() => $this->di->invoke($controller, $method, $context->getArguments());
			
			// Build a nested chain of around aspects in reverse order.
			// Reverse order ensures the first declared aspect becomes outermost wrapper.
			// Each aspect wraps the previous proceed function, creating nested calls.
			foreach (array_reverse($aroundAspects) as $aspect) {
				$currentProceed = $proceed; // Capture current proceed function in closure
				$proceed = fn() => $aspect->around($context, $currentProceed); // Wrap with this aspect
			}
			
			// Execute the complete chain starting from the outermost aspect
			return $proceed();
		}
	}