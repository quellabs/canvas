<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * @Annotation
	 * @Target("METHOD")
	 * Annotation for declaring aspect-oriented method interception
	 */
	class InterceptWith implements AnnotationInterface {
		
		/**
		 * Raw annotation parameters from the docblock
		 * @var array<string, mixed>
		 */
		private array $parameters;
		
		/** @var string The aspect class to use for this interception */
		private string $interceptClass;
		
		/** @var int Priority */
		private int $priority;
		
		/**
		 * Constructs the annotation with parameters parsed from the docblock
		 * @param array<string, mixed> $parameters Parsed annotation parameters (value, type, priority, and aspect-specific params)
		 */
		public function __construct(array $parameters) {
			$value = $parameters['value'] ?? null;
			$priority = $parameters['priority'] ?? null;
			
			if (!isset($value) || !is_string($value) || !class_exists($value)) {
				throw new \InvalidArgumentException("InterceptWith needs a valid aspect class");
			}
			
			if (isset($priority) && !is_integer($priority)) {
				throw new \InvalidArgumentException("Invalid priority for InterceptWith. Needs to be an integer");
			}
			
			$this->parameters = $parameters;
			$this->interceptClass = $value;
			$this->priority = is_integer($priority) ? $priority : 0;
		}
		
		/**
		 * Returns all raw annotation parameters including internal ones
		 * @return array<string, mixed> Complete parameters array with all keys and values
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Returns the fully-qualified class name of the aspect to execute
		 * @return string The aspect class name from the 'value' parameter (e.g., "App\\Aspects\\CacheAspect")
		 */
		public function getInterceptClass(): string {
			return $this->interceptClass;
		}
		
		/**
		 * Returns the execution priority for aspect ordering
		 * Higher priority values execute first. Default is 0.
		 * Used to control aspect execution order when multiple aspects apply to the same method.
		 * Example: Authentication (priority=100) should run before caching (priority=10)
		 * @return int Priority value (defaults to 0 if not specified or invalid)
		 */
		public function getPriority(): int {
			return $this->priority;
		}
	}