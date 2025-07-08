<?php
	
	namespace Quellabs\Canvas\AOP;
	
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Session\SessionInterface;
	
	/**
	 * Context object that encapsulates information about a method call.
	 * Used in AOP (Aspect-Oriented Programming) scenarios to provide
	 * interceptors and decorators with complete method execution context.
	 */
	class MethodContext implements \Quellabs\Contracts\AOP\MethodContext {
		
		private Request $request;
		private object $target;
		private string $methodName;
		private array $arguments;
		private \ReflectionMethod $reflection;
		
		/**
		 * Initialize the method context with all relevant call information.
		 * @param Request $request
		 * @param object $target The original object instance on which the method is being called
		 * @param string $methodName Name of the method being invoked
		 * @param array $arguments Array of arguments passed to the method
		 * @param \ReflectionMethod $reflection Reflection object for accessing method metadata
		 */
		public function __construct(
			Request $request,              // The request object
			object $target,                // The original object instance
			string $methodName,            // Method being called
			array $arguments,              // Method parameters
			\ReflectionMethod $reflection  // For metadata
		) {
			$this->request = $request;
			$this->target = $target;
			$this->methodName = $methodName;
			$this->arguments = $arguments;
			$this->reflection = $reflection;
		}
		
		/**
		 * Get the target object instance.
		 * @return object The original object on which the method is being called
		 */
		public function getTarget(): object {
			return $this->target;
		}
		
		/**
		 * Get the name of the method being called.
		 * @return string The method name
		 */
		public function getMethodName(): string {
			return $this->methodName;
		}
		
		/**
		 * Get all arguments passed to the method.
		 * @return array Array of method arguments in order
		 */
		public function getArguments(): array {
			return $this->arguments;
		}
		
		/**
		 * Get the ReflectionMethod object for accessing method metadata.
		 * Provides access to method visibility, parameters, return type, etc.
		 * @return \ReflectionMethod The reflection object for the method
		 */
		public function getReflection(): \ReflectionMethod {
			return $this->reflection;
		}
		
		/**
		 * Returns the request object
		 * @return Request
		 */
		public function getRequest(): Request {
			return $this->request;
		}
		
		/**
		 * Sets the request object
		 * @param Request $request
		 * @return void
		 */
		public function setRequest(Request $request): void {
			$this->request = $request;
		}
		
		/**
		 * Returns the method arguments
		 * @return array
		 */
		public function getMethodArguments(): array {
			$result = [];
			
			foreach($this->getReflection()->getParameters() as $parameter) {
				$result[] = [
					'name'          => $parameter->getName(),
					'type'          => $parameter->getType() ? $parameter->getType()->getName() : null,
					'default_value' => $parameter->isDefaultValueAvailable() ? $parameter->getDefaultValue() : null
				];
			}
			
			return $result;
		}
	}