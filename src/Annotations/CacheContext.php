<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * CacheContext annotation class
	 */
	class CacheContext implements AnnotationInterface {
		
		/** @var array All parameters passed to the annotation */
		protected array $parameters;
		
		/**
		 * CacheNamespace constructor
		 * @param array $parameters The annotation parameters (expects 'value' key)
		 */
		public function __construct(array $parameters) {
			$this->parameters = $parameters;
		}
		
		/**
		 * Returns all annotation parameters
		 * @return array The complete parameters array
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
	}