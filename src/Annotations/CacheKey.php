<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * CacheKey annotation class for defining cache keys in the Canvas framework
	 *
	 * This annotation is used to specify cache keys for methods or classes,
	 * allowing the caching system to identify and manage cached data effectively.
	 *
	 * Usage example:
	 * @CacheKey(key="user_profile_123")
	 */
	class CacheKey implements AnnotationInterface {
		
		/** @var array All parameters passed to the annotation */
		protected array $parameters;
		
		/**
		 * CacheKey constructor
		 * @param array $parameters The annotation parameters (expects 'value' key)
		 * @throws \InvalidArgumentException When no value is provided for the cache key
		 */
		public function __construct(array $parameters) {
			$this->parameters = $parameters;
			
			// Validate that a cache key value has been provided
			if (empty($this->parameters["key"])) {
				throw new \InvalidArgumentException("CacheKey annotation requires a value");
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
		public function getKey(): string {
			return $this->parameters["key"];
		}
	}