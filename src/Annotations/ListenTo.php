<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * Declares that an annotated method should be connected to a named signal.
	 *
	 * Usage on a signal provider method:
	 * @ListenTo("user.created")
	 * @ListenTo("user.created", priority=10)
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
		
		/** @var string The name of the signal */
		private string $signalName;
		
		/** @var int Priority */
		private int $priority;
		
		/**
		 * @param array<string, mixed> $parameters Parsed annotation parameters, expecting at minimum "value"
		 */
		public function __construct(array $parameters) {
			$value = $parameters['value'] ?? null;
			$priority = $parameters['priority'] ?? null;
			
			if (!isset($value) || !is_string($value)) {
				throw new \InvalidArgumentException("ListenTo needs a valid signal name");
			}
			
			if (isset($priority) && !is_integer($priority)) {
				throw new \InvalidArgumentException("Invalid priority for ListenTo. Needs to be an integer");
			}
			
			$this->parameters = $parameters;
			$this->signalName = $value;
			$this->priority = is_integer($priority) ? $priority : 0;
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
			return $this->signalName;
		}
		
		/**
		 * Returns the connection priority. Higher values connect before lower ones.
		 * Defaults to 0 if not specified: @ListenTo("signal.name", priority=10)
		 * @return int
		 */
		public function getPriority(): int {
			return $this->priority;
		}
	}