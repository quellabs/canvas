<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * @Annotation
	 * Specifies the DI container context to use when resolving a particular
	 * constructor or method parameter. Accepts arbitrary context keys via the
	 * variadic tail, so the same named arguments work identically as a docblock
	 * annotation or a native PHP attribute.
	 */
	#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
	class WithContext implements AnnotationInterface {

		/**
		 * Array of route parameters including route path and HTTP methods
		 * @var array<string, mixed>
		 */
		private array $parameters;

		/**
		 * @var string The parameter to add context for
		 */
		private string $contextParameter;

		/**
		 * WithContext constructor
		 * @param string $parameter The method parameter to add context for
		 * @param mixed ...$context Arbitrary context options
		 */
		public function __construct(string $parameter, mixed ...$context) {
			$parameters = ['parameter' => $parameter];

			foreach ($context as $key => $value) {
				if (!is_string($key)) {
					throw new \InvalidArgumentException("WithContext context options must be named arguments");
				}

				$parameters[$key] = $value;
			}

			$this->parameters = $parameters;
			$this->contextParameter = $parameter;
		}
		
		/**
		 * Returns all route parameters
		 * @return array<string, mixed> The complete array of route parameters
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Returns the WithContext parameter
		 * @return string
		 */
		public function getParameter(): string {
			return $this->contextParameter;
		}
		
		/**
		 * Returns the WithContext context
		 * @return array<string, mixed>
		 */
		public function getContext(): array {
			$result = [];
			
			foreach ($this->parameters as $key => $value) {
				// Parameter is the context parameter
				// Not needed in context bucket
				if ($key == "parameter") {
					continue;
				}
				
				$result[$key] = $value;
			}
			
			return $result;
		}
	}
	