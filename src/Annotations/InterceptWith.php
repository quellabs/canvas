<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * Annotation for declaring aspect-oriented method interception
	 *
	 * Usage examples:
	 * @InterceptWith(LoggingAspect::class)
	 * @InterceptWith(CacheAspect::class, ttl=3600, priority=10)
	 */
	class InterceptWith implements AnnotationInterface {
		
		/**
		 * Raw annotation parameters from the docblock
		 * @var array
		 */
		private array $parameters;
		
		/**
		 * Constructs the annotation with parameters parsed from the docblock
		 * @param array $parameters Parsed annotation parameters (value, type, priority, and aspect-specific params)
		 */
		public function __construct(array $parameters) {
			$this->parameters = $parameters;
		}
		
		/**
		 * Returns all raw annotation parameters including internal ones
		 * @return array Complete parameters array with all keys and values
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Returns the fully-qualified class name of the aspect to execute
		 * @return string The aspect class name from the 'value' parameter (e.g., "App\\Aspects\\CacheAspect")
		 */
		public function getInterceptClass(): string {
			return $this->parameters['value'];
		}
		
		/**
		 * Returns the execution priority for aspect ordering
		 * Higher priority values execute first. Default is 0.
		 * Used to control aspect execution order when multiple aspects apply to the same method.
		 * Example: Authentication (priority=100) should run before caching (priority=10)
		 * @return int Priority value (defaults to 0 if not specified or invalid)
		 */
		public function getPriority(): int {
			if (!isset($this->parameters['priority']) || !is_numeric($this->parameters['priority'])) {
				return 0;
			}
			
			return (int)$this->parameters['priority'];
		}
	}