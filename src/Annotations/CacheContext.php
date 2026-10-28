<?php

	namespace Quellabs\Canvas\Annotations;

	use Quellabs\AnnotationReader\AnnotationInterface;

	/**
	 * @Annotation
	 * @Target("METHOD")
	 * CacheContext annotation class. Accepts arbitrary cache configuration
	 * (e.g. namespace, ttl) for one @WithContext-resolved context value — not
	 * provider selection, which is @WithContext's job. Repeatable: add one
	 * @CacheContext per context the method's @WithContext can resolve to, plus
	 * an optional untagged one (no `context` argument) as the default used when
	 * none of the tagged ones match. The same named arguments work identically
	 * as a docblock annotation or a native PHP attribute.
	 */
	#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
	class CacheContext implements AnnotationInterface {

		/**
		 * @var string|null The @WithContext-resolved context this instance configures, or null for the default
		 */
		protected ?string $context;

		/**
		 * @var array<string, mixed> All remaining parameters passed to the annotation
		 */
		protected array $parameters;

		/**
		 * CacheContext constructor
		 * @param string|null $context The @WithContext-resolved context this instance applies to, or null to act as the default
		 * @param mixed ...$parameters Arbitrary cache options (e.g. namespace, ttl)
		 */
		public function __construct(?string $context = null, mixed ...$parameters) {
			$result = [];

			foreach ($parameters as $key => $value) {
				if (!is_string($key)) {
					throw new \InvalidArgumentException("CacheContext options must be named arguments");
				}

				$result[$key] = $value;
			}

			$this->context = $context;
			$this->parameters = $result;
		}

		/**
		 * Returns the @WithContext-resolved context this instance applies to
		 * @return string|null Null when this instance is the untagged default
		 */
		public function getContext(): ?string {
			return $this->context;
		}

		/**
		 * Returns all annotation parameters, excluding `context`
		 * @return array<string, mixed> The complete parameters array
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
	}
