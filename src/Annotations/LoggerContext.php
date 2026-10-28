<?php

	namespace Quellabs\Canvas\Annotations;

	use Quellabs\AnnotationReader\AnnotationInterface;

	/**
	 * @Annotation
	 * @Target("METHOD")
	 * LoggerContext annotation class. Accepts arbitrary logger configuration
	 * (e.g. logfile, channel) for one @WithContext-resolved context value —
	 * not handler selection, which is @WithContext's job. Repeatable: add one
	 * @LoggerContext per context the method's @WithContext can resolve to, plus
	 * an optional untagged one (no `context` argument) as the default used when
	 * none of the tagged ones match. Read directly off the method by
	 * LoggerInterfaceProvider, independent of @WithContext. The same named
	 * arguments work identically as a docblock annotation or a native PHP attribute.
	 */
	#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
	class LoggerContext implements AnnotationInterface {

		/**
		 * @var string|null The @WithContext-resolved context this instance configures, or null for the default
		 */
		protected ?string $context;

		/**
		 * @var array<string, mixed> All remaining parameters passed to the annotation
		 */
		protected array $parameters;

		/**
		 * LoggerContext constructor
		 * @param string|null $context The @WithContext-resolved context this instance applies to, or null to act as the default
		 * @param mixed ...$parameters Arbitrary logger options (e.g. logfile, channel)
		 */
		public function __construct(?string $context = null, mixed ...$parameters) {
			$result = [];

			foreach ($parameters as $key => $value) {
				if (!is_string($key)) {
					throw new \InvalidArgumentException("LoggerContext options must be named arguments");
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
