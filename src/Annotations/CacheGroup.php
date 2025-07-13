<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * CacheKey annotation class for defining cache groups in the Canvas framework
	 */
	class CacheGroup implements AnnotationInterface {
		
		/** @var array All parameters passed to the annotation */
		protected array $parameters;
		
		/**
		 * CacheGroup constructor
		 * @param array $parameters The annotation parameters (expects 'value' key)
		 * @throws \InvalidArgumentException When no value is provided for the cache group
		 */
		public function __construct(array $parameters) {
			// Store parameters
			$this->parameters = $parameters;
			
			// Validate that a cache key value has been provided
			if (empty($this->parameters["value"])) {
				throw new \InvalidArgumentException("CacheGroup annotation requires a value");
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
		 * Returns the cache key value
		 * @return string The cache key value
		 */
		public function getGroup(): string {
			return $this->parameters["value"];
		}
	}