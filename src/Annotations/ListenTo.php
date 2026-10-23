<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	use Quellabs\AnnotationReader\Annotation\ReflectsAnnotationParameters;
	
	/**
	 * @Annotation
	 * @Target("METHOD")
	 * Declares that an annotated method should be connected to a named signal.
	 */
	#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
	class ListenTo implements AnnotationInterface {
		use ReflectsAnnotationParameters;
		private string $value;

		
		/**
		 * @var int Priority
		 */
		private int $priority;
		
		/**
		 * Constructs the ListenTo annotation.
		 * @param string $value
		 * @param int $priority
		 * @return void
		 */
		public function __construct(string $value, int $priority = 0) {
			$this->value = $value;
			$this->priority = $priority;
		}
		

		
		/**
		 * Returns the signal name this method should be connected to.
		 * Corresponds to the unnamed first argument: @ListenTo("signal.name")
		 * @return string
		 */
		public function getName(): string {
			return $this->value;
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
