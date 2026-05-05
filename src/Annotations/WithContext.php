<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * Specifies the DI container context to use when resolving a particular
	 * constructor or method parameter.
	 *
	 * Usage:
	 *   @WithContext(parameter="templateEngine", context="blade")
	 *   public function render(TemplateEngineInterface $templateEngine): string
	 *
	 * This causes $templateEngine to be resolved via $container->for('blade')
	 * instead of the default container.
	 */
	class WithContext implements AnnotationInterface {
		
		/**
		 * Array of route parameters including route path and HTTP methods
		 * @var array<string, mixed>
		 */
		private array $parameters;
		
		/**
		 * WithContext constructor
		 * @param array<string, mixed> $parameters
		 */
		public function __construct(array $parameters) {
			$this->parameters = $parameters;
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
			return $this->parameters['parameter'] ?? '';
		}
		
		/**
		 * Returns the WithContext context
		 * @return string
		 */
		public function getContext(): string {
			return $this->parameters['context'] ?? '';
		}
	}