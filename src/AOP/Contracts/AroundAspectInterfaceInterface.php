<?php
	
	namespace Quellabs\Canvas\AOP\Contracts;
	
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	
	/**
	 * Interface for aspect-oriented programming "around" advice.
	 */
	interface AroundAspectInterfaceInterface extends AspectAnnotationInterface {
		
		/**
		 * Wraps around the target method execution with full control.
		 *
		 * This method is called instead of the original method and gives
		 * complete control over the execution flow. The implementer decides
		 * when (or if) to call the original method via the $proceed callback.
		 * This allows for pre-processing, post-processing, conditional execution,
		 * exception handling, and result modification.
		 *
		 * @param MethodContextInterface $context Contains metadata about the intercepted method
		 * @param callable $proceed Callback function that executes the original method.
		 *                          Call this to invoke the wrapped method with its
		 *                          original arguments. Can be called zero, one, or
		 *                          multiple times depending on the aspect's logic.
		 *
		 * @return mixed The result to return in place of the original method.
		 *               This can be the result from $proceed(), a modified version
		 *               of it, or a completely different value.
		 */
		public function around(MethodContextInterface $context, callable $proceed): mixed;
	}