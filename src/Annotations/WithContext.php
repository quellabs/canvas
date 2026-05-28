<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * @Annotation
	 * Specifies the DI container context to use when resolving a particular
	 * constructor or method parameter.
	 */
	class WithContext implements AnnotationInterface {
		
		/**
		 * Array of route parameters including route path and HTTP methods
		 * @var array<string, mixed>
		 */
		private array $parameters;
		
		/** @var string The parameter to add context for */
		private string $contextParameter;
		
		/**
		 * WithContext constructor
		 * @param array<string, mixed> $parameters
		 */
		public function __construct(array $parameters) {
			$parameter = $parameters['parameter'] ?? null;
			
			if (!isset($parameter) || !is_string($parameter)) {
				throw new \InvalidArgumentException("WithContext needs a parameter to add context to");
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
				
				// DI system uses 'provider' instead of 'context'
				if ($key === 'context') {
					$key = 'provider';
				}
				
				$result[$key] = $value;
			}
			
			return $result;
		}
	}