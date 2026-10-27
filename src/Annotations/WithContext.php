<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * @Annotation
	 * Specifies the DI container context to use when resolving a particular
	 * constructor or method parameter. `context` is either a literal tag (e.g.
	 * "redis") or a class-string naming a ContextProviderInterface provider,
	 * resolved at request time by CanvasAutowirer.
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
		 * @param string $context The context tag, or a ContextProviderInterface class-string
		 */
		public function __construct(string $parameter, string $context) {
			$this->parameters = ['parameter' => $parameter, 'context' => $context];
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
			return ['context' => $this->parameters['context']];
		}
	}
	