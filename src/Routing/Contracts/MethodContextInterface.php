<?php
	
	namespace Quellabs\Canvas\Routing\Contracts;
	
	use Quellabs\Contracts\Context\MethodContext;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Interface for context objects that encapsulate information about a method call.
	 * Used in AOP (Aspect-Oriented Programming) scenarios to provide
	 * interceptors and decorators with complete method execution context.
	 */
	interface MethodContextInterface extends MethodContext {
		
		/**
		 * Get the class object
		 * @return object The class being called
		 */
		public function getClass(): object;
		
		/**
		 * Get all arguments passed to the method.
		 * @return array Array of method arguments in order
		 */
		public function getArguments(): array;
		
		/**
		 * Returns the request object
		 * @return Request
		 */
		public function getRequest(): Request;
		
		/**
		 * Sets the request object
		 * @param Request $request
		 * @return void
		 */
		public function setRequest(Request $request): void;
	}