<?php
	
	namespace Quellabs\Canvas\Annotations;
	
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
	class WithContext {
		
		/**
		 * The parameter name this context applies to
		 * @var string
		 */
		public string $parameter;
		
		/**
		 * The container context to use when resolving the parameter
		 * @var string
		 */
		public string $context;
		
		/**
		 * WithContext constructor
		 * @param string $parameter The name of the parameter to apply context to
		 * @param string $context The container context string passed to $container->for()
		 */
		public function __construct(string $parameter, string $context) {
			$this->parameter = $parameter;
			$this->context = $context;
		}
	}