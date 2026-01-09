<?php
	
	namespace Quellabs\Contracts\AOP;
	
	namespace Quellabs\Canvas\AOP\Contracts;
	
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	
	/**
	 * Interface for implementing request-based aspects in the AOP framework.
	 */
	interface RequestAspectInterface extends AspectAnnotationInterface {
		
		/**
		 * Transform the request before it's processed by business logic.
		 * Modify the request object directly - no return value needed.
		 * @param MethodContextInterface $context Contains metadata about the intercepted method
		 * @return void
		 */
		public function transformRequest(MethodContextInterface $context): void;
	}