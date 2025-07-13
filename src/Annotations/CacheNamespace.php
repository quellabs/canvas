<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * CacheKey annotation class for defining cache groups in the Canvas framework
	 */
	class CacheNamespace implements AnnotationInterface {
		
		/** @var array All parameters passed to the annotation */
		protected array $parameters;
		
		/**
		 * CacheNamespace constructor
		 * @param array $parameters The annotation parameters (expects 'value' key)
		 * @throws \InvalidArgumentException When no value is provided for the cache group
		 */
		public function __construct(array $parameters) {
			// Store parameters
			$this->parameters = $parameters;
			
			// Validate that a cache key value has been provided
			if (empty($this->parameters["value"])) {
				throw new \InvalidArgumentException("CacheNamespace annotation requires a value");
			}
		}
		
		/**
		 * Returns all annotation parameters
		 * @return array The complete parameters array
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Returns the namespace's value
		 * @return string The cache key value
		 */
		public function getNamespace(): string {
			return $this->parameters["value"];
		}
	}