<?php
	
	namespace Quellabs\Canvas\AOP\Contracts;
	
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Interface for aspect-oriented programming "after" advice.
	 *
	 * After aspects are executed following the completion of the target method
	 * and are designed to modify the response object in-place rather than
	 * replace it entirely. This ensures all after aspects in the chain
	 * can contribute to the final response.
	 */
	interface AfterAspectInterfaceInterface extends AspectAnnotationInterface {
		
		/**
		 * Executes after the target method has completed.
		 *
		 * This method is called automatically by the aspect system after
		 * the intercepted method finishes execution. It receives both the
		 * method context and the response object, which should be modified
		 * in-place to add headers, cookies, perform logging, or other
		 * post-processing tasks.
		 *
		 * Common use cases:
		 * - Adding or modifying response headers
		 * - Setting cookies
		 * - Logging response metrics
		 * - Adding CORS headers
		 * - Compressing response content
		 * - Adding security headers
		 *
		 * @param MethodContextInterface $context Contains metadata about the intercepted method
		 * @param Response $response The response object to be modified in-place.
		 *                          This is the response returned by the controller method.
		 *
		 * @return void No return value expected
		 */
		public function after(MethodContextInterface $context, Response $response): void;
	}