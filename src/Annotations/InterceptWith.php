<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	use Quellabs\Canvas\AOP\Contracts\AspectAnnotationInterface;
	
	/**
	 * @Annotation
	 * @Target("CLASS")
	 * @Target("METHOD")
	 * Annotation for declaring aspect-oriented method interception. Accepts arbitrary
	 * aspect-specific keys via the variadic tail, so the same named arguments work
	 * identically as a docblock annotation or a native PHP attribute.
	 */
	#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
	class InterceptWith implements AnnotationInterface {

		/**
		 * Raw annotation parameters, including aspect-specific ones
		 * @var array<string, mixed>
		 */
		private array $parameters;

		/**
		 * @var string The aspect class to use for this interception
		 */
		private string $interceptClass;

		/**
		 * @var int Priority
		 */
		private int $priority;

		/**
		 * Constructs the annotation
		 * @param string $value The aspect class to execute
		 * @param int $priority Execution priority; higher runs first
		 * @param mixed ...$options Arbitrary aspect-specific parameters
		 */
		public function __construct(string $value, int $priority = 0, mixed ...$options) {
			if (!class_exists($value)) {
				throw new \InvalidArgumentException("InterceptWith needs a valid aspect class");
			}

			if (!is_subclass_of($value, AspectAnnotationInterface::class)) {
				throw new \InvalidArgumentException(sprintf(
					"InterceptWith class '%s' must implement %s (via BeforeAspectInterface, AfterAspectInterface, AroundAspectInterface, or RequestAspectInterface)",
					$value,
					AspectAnnotationInterface::class
				));
			}

			$parameters = ['value' => $value, 'priority' => $priority];

			foreach ($options as $key => $optionValue) {
				if (!is_string($key)) {
					throw new \InvalidArgumentException("InterceptWith aspect-specific options must be named arguments");
				}

				$parameters[$key] = $optionValue;
			}

			$this->parameters = $parameters;
			$this->interceptClass = $value;
			$this->priority = $priority;
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
