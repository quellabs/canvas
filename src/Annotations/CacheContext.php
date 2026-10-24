<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * @Annotation
	 * @Target("METHOD")
	 * CacheContext annotation class. Accepts arbitrary cache options; the same named
	 * arguments work identically as a docblock annotation or a native PHP attribute.
	 */
	#[\Attribute(\Attribute::TARGET_METHOD)]
	class CacheContext implements AnnotationInterface {

		/**
		 * @var array<string, mixed> All parameters passed to the annotation
		 */
		protected array $parameters;

		/**
		 * CacheContext constructor
		 * @param mixed ...$parameters Arbitrary cache options (e.g. namespace, driver, ttl)
		 */
		public function __construct(mixed ...$parameters) {
			$result = [];

			foreach ($parameters as $key => $value) {
				if (!is_string($key)) {
					throw new \InvalidArgumentException("CacheContext options must be named arguments");
				}

				$result[$key] = $value;
			}

			$this->parameters = $result;
		}
		
		/**
		 * Returns all annotation parameters
		 * @return array<string, mixed> The complete parameters array
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
	}
