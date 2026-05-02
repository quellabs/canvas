<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * Declares that an annotated method should be connected to a named signal.
	 *
	 * Usage on a signal provider method:
	 *   @ListenTo("user.created")
	 *   @ListenTo("user.created", priority=10)
	 *
	 * The annotation reader passes all annotation parameters as a key-value array.
	 * "value" holds the signal name (the unnamed first argument by convention),
	 * "priority" is optional and defaults to 0 if omitted.
	 */
	class ListenTo implements AnnotationInterface {
		
		/**
		 * @var array<string, mixed> Raw annotation parameters as parsed by the annotation reader
		 */
		protected array $parameters;
		
		/**
		 * @param array<string, mixed> $parameters Parsed annotation parameters, expecting at minimum "value"
		 */
		public function __construct(array $parameters) {
			$this->parameters = $parameters;
		}
		
		/**
		 * Returns all raw annotation parameters
		 * @return array<string, mixed>
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Returns the signal name this method should be connected to.
		 * Corresponds to the unnamed first argument: @ListenTo("signal.name")
		 * @return string
		 */
		public function getName(): string {
			return $this->parameters["value"];
		}
		
		/**
		 * Returns the connection priority. Higher values connect before lower ones.
		 * Defaults to 0 if not specified: @ListenTo("signal.name", priority=10)
		 * @return int
		 */
		public function getPriority(): int {
			return $this->parameters["priority"] ?? 0;
		}
	}