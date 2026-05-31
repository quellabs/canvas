<?php

	/** @noinspection PhpDocSignatureInspection */
	
	namespace Quellabs\Canvas\DependencyInjection;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\DependencyInjection\Autowiring\Autowirer;
	use Quellabs\Contracts\DependencyInjection\ContainerInterface;
	use Quellabs\Canvas\Annotations\WithContext;
	use Quellabs\Contracts\Context\MethodContextInterface;
	
	/**
	 * Canvas-aware autowirer that extends the base autowirer with annotation-driven
	 * contextual dependency injection via @WithContext.
	 *
	 * The base Autowirer has no knowledge of annotations — it lives in the DI package
	 * which has no dependency on AnnotationReader or Canvas configuration. This subclass
	 * adds that layer by reading @WithContext annotations from method docblocks and
	 * slotting the resolved context into the parameter metadata before resolution runs.
	 *
	 * @phpstan-import-type ParameterMeta from Autowirer
	 */
	class CanvasAutowirer extends Autowirer {
		
		/**
		 * Metadata array for the current parameter being resolved, populated from
		 * the @WithContext annotation. Null when no annotation was declared, causing
		 * resolveType() to use the default container.
		 * @var array<string, mixed>|null
		 */
		private ?array $currentParamContext = null;
		
		/**
		 * Annotation reader used to extract @WithContext annotations from method docblocks.
		 * Configured by the Kernel with the correct cache settings for the current environment.
		 * @var AnnotationReader
		 */
		private AnnotationReader $annotationReader;
		
		/**
		 * CanvasAutowirer constructor
		 * @param ContainerInterface $container The DI container used for dependency resolution
		 * @param AnnotationReader $annotationReader Pre-configured annotation reader from the Kernel
		 */
		public function __construct(ContainerInterface $container, AnnotationReader $annotationReader) {
			parent::__construct($container);
			$this->annotationReader = $annotationReader;
		}
		
		/**
		 * Extends base parameter resolution with @WithContext annotation support.
		 *
		 * Reads @WithContext annotations from the method docblock and attaches a
		 * 'context' key to any parameter entry whose name matches an annotation.
		 * resolveType() reads 'context' and uses it to select the correct container.
		 *
		 * Annotation parsing failures are silently swallowed so that methods without
		 * docblocks, or with unrelated parse errors, fall through to normal resolution.
		 *
		 * @param class-string $className The fully qualified class name containing the method
		 * @param string $methodName The name of the method to reflect
		 * @return array<int, ParameterMeta> Parameter metadata array, each entry optionally containing 'context'
		 */
		protected function getMethodParameters(string $className, string $methodName): array {
			// Delegate to parent for base parameter metadata (types, defaults, names)
			$params = parent::getMethodParameters($className, $methodName);
			
			// Build a map of param name -> metadata array from @WithContext annotations
			$withContextMap = [];
			
			try {
				$annotations = $this->annotationReader->getMethodAnnotations(
					$className,
					$methodName,
					WithContext::class
				);
				
				foreach ($annotations as $annotation) {
					// This was added to make phpstan happy
					if (!$annotation instanceof WithContext) {
						continue;
					}
					
					$withContextMap[$annotation->getParameter()] = $annotation->getContext();
				}
			} catch (\Throwable) {
				// Annotation parsing failed or no docblock present — proceed without
				// context, falling back to standard container resolution for all params
			}
			
			// Attach context to any parameter entry that has a matching annotation
			if (!empty($withContextMap)) {
				foreach ($params as &$param) {
					if (isset($withContextMap[$param['name']])) {
						$param['context'] = $withContextMap[$param['name']];
					}
				}
			}
			
			return $params;
		}
		
		/**
		 * Extends base parameter resolution to support @WithContext annotation.
		 * Sets the current parameter's context before delegating to the base class,
		 * so that resolveType() can pick it up and use the correct container.
		 * @param ParameterMeta $param Parameter metadata, optionally containing 'context' from @WithContext
		 * @param array<string, mixed> $parameters User-provided parameter values
		 * @param MethodContextInterface|null $methodContext Context object for dependency injection
		 * @param string $className Class name for error reporting
		 * @param string $methodName Method name for error reporting
		 * @return mixed The resolved parameter value
		 */
		protected function resolveParameter(
			array          $param,
			array          $parameters,
			?MethodContextInterface $methodContext,
			string         $className,
			string         $methodName
		): mixed {
			// Store the context for this parameter so resolveType() can use it.
			// Null when no @WithContext annotation was declared, which causes
			// resolveType() to fall back to the default container.
			$this->currentParamContext = $param['context'] ?? null;
			
			try {
				return parent::resolveParameter($param, $parameters, $methodContext, $className, $methodName);
			} finally {
				// Always reset regardless of success or exception, so the context
				// from this parameter never bleeds into the next one
				$this->currentParamContext = null;
			}
		}
		
		/**
		 * Overrides base type resolution to use a contextual container clone when
		 * a @WithContext annotation has been declared for the current parameter.
		 *
		 * @param class-string $type The fully qualified class or interface name to resolve
		 * @param array<string, mixed> $parameters Additional parameters for resolution
		 * @param MethodContextInterface|null $methodContext
		 * @return object|null The resolved instance, or null
		 */
		protected function resolveType(string $type, array $parameters, ?MethodContextInterface $methodContext): ?object {
			// When @WithContext is active, temporarily swap the container to a scoped
			// clone for this resolution only. The original is restored in the finally
			// block so the next parameter resolves from the default container.
			$originalContainer = $this->container;
			
			if ($this->currentParamContext) {
				$this->container = $this->container->for($this->currentParamContext);
			}
			
			try {
				return parent::resolveType($type, $parameters, $methodContext);
			} finally {
				$this->container = $originalContainer;
			}
		}
	}