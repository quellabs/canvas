<?php

	namespace Quellabs\Canvas\Annotations;

	use Quellabs\AnnotationReader\AnnotationInterface;

	/**
	 * @Annotation
	 * @Target("METHOD")
	 * LoggerContext annotation class. Accepts arbitrary logger options (e.g.
	 * handler, logfile, channel); the same named arguments work identically as
	 * a docblock annotation or a native PHP attribute. Read directly off the
	 * method by LoggerInterfaceProvider, independent of @WithContext.
	 */
	#[\Attribute(\Attribute::TARGET_METHOD)]
	class LoggerContext implements AnnotationInterface {

		/**
		 * @var array<string, mixed> All parameters passed to the annotation
		 */
		protected array $parameters;

		/**
		 * LoggerContext constructor
		 * @param mixed ...$parameters Arbitrary logger options (e.g. handler, logfile, channel)
		 */
		public function __construct(mixed ...$parameters) {
			$result = [];

			foreach ($parameters as $key => $value) {
				if (!is_string($key)) {
					throw new \InvalidArgumentException("LoggerContext options must be named arguments");
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
