<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * InterceptWith annotation class for method interception
	 */
	class InterceptWith implements AnnotationInterface {
		
		/**
		 * Array containing the annotation parameters
		 * @var array
		 */
		private array $parameters;
		
		/**
		 * InterceptWith constructor
		 * @param array $parameters The annotation parameters containing 'value' and 'type' keys
		 */
		public function __construct(array $parameters) {
			$this->parameters = $parameters;
		}
		
		/**
		 * Get all annotation parameters
		 * @return array The complete parameters array
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Get the interceptor class name
		 * @return string The interceptor class name from the 'value' parameter
		 */
		public function getInterceptClass(): string {
			return $this->parameters['value'];
		}
		
		/**
		 * Get the interception type
		 *
		 * Returns when the interceptor should be executed relative to the target method:
		 * - 'before': Execute interceptor before the target method
		 * - 'after': Execute interceptor after the target method completes
		 * - 'around': Execute interceptor around the target method (full control)
		 *
		 * @return string The interception type ('before', 'after', or 'around')
		 */
		public function getInterceptType(): string {
			return $this->parameters['type'];
		}
	}