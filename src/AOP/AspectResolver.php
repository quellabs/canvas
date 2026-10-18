<?php

	namespace Quellabs\Canvas\AOP;

	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Collection\AnnotationCollection;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\AOP\Contracts\NonStackableAspectInterface;
	use Quellabs\Canvas\Annotations\InterceptWith;

	/**
	 * @phpstan-type AspectDefinition array{class: class-string, parameters: array<string, mixed>, priority: int}
	 */
	readonly class AspectResolver {

		/**
		 * AnnotationReader is used to read annotations in docblocks
		 * @var AnnotationReader
		 */
		private AnnotationReader $annotationReader;

		/**
		 * AspectDispatcher constructor
		 * @param AnnotationReader $annotationReader
		 */
		public function __construct(AnnotationReader $annotationReader) {
			$this->annotationReader = $annotationReader;
		}

		/**
		 * Resolves all aspects that should be applied to a controller method
		 * Aspects are sorted by priority within each class in the inheritance hierarchy.
		 * Execution order: grandparent → parent → current class → method
		 * Within each level, higher priority executes first.
		 * @param object|class-string $controller The controller instance
		 * @param string $method The method name being called
		 * @return array<int, AspectDefinition> Array of aspect definitions sorted by inheritance hierarchy and priority
		 * @throws AnnotationReaderException
		 */
		public function resolve(object|string $controller, string $method): array {
			$allAspects = [];

			// Process each class in the inheritance chain (parent to child)
			$inheritanceChain = $this->getInheritanceChain($controller);

			foreach ($inheritanceChain as $class) {
				// Fetch the annotations
				$classAnnotations = $this->annotationReader->getClassAnnotations($class, InterceptWith::class);

				// Convert the annotations to aspects
				$aspects = $this->convertAnnotationsToAspects($classAnnotations);

				// Sort by priority within this class level
				usort($aspects, fn($a, $b) => $b['priority'] <=> $a['priority']);

				// Add to result, maintaining parent-to-child order. A NonStackableAspectInterface
				// aspect re-declared here replaces its ancestor's declaration rather than joining it.
				$allAspects = $this->mergeAspects($allAspects, $aspects);
			}

			// Get method-level annotations
			$methodAnnotations = $this->annotationReader->getMethodAnnotations($controller, $method, InterceptWith::class);

			// Convert the annotations to aspects
			$methodAspects = $this->convertAnnotationsToAspects($methodAnnotations);

			// Sort method aspects by priority
			usort($methodAspects, fn($a, $b) => $b['priority'] <=> $a['priority']);

			// Combine: all class-level aspects (parent to child) → method aspects, same
			// override rule applied
			return $this->mergeAspects($allAspects, $methodAspects);
		}

		/**
		 * Merges a more specific level's aspects into the accumulated list. For any aspect
		 * class implementing NonStackableAspectInterface, a declaration at this level replaces
		 * one inherited from a less specific level instead of both applying; every other aspect
		 * class keeps stacking as before. Aspects declared at the same level are never
		 * affected by this, even when they share a class.
		 * @param array<int, AspectDefinition> $existing Aspects accumulated from less specific levels
		 * @param array<int, AspectDefinition> $new Aspects declared at the current, more specific level
		 * @return array<int, AspectDefinition>
		 */
		private function mergeAspects(array $existing, array $new): array {
			$nonStackableNewClasses = array_unique(array_filter(
				array_column($new, 'class'),
				fn(string $class) => is_subclass_of($class, NonStackableAspectInterface::class)
			));

			$existing = array_values(array_filter(
				$existing,
				fn(array $aspect) => !in_array($aspect['class'], $nonStackableNewClasses, true)
			));

			return array_merge($existing, $new);
		}

		/**
		 * Convert annotation instances to aspect definitions with parameters and priority
		 * @param AnnotationCollection $annotations Collection of InterceptWith annotations
		 * @return array<int, AspectDefinition> Array of aspect definitions
		 */
		private function convertAnnotationsToAspects(AnnotationCollection $annotations): array {
			$aspects = [];

			foreach ($annotations as $annotation) {
				// Validate annotation is of type InterceptWith
				if (!$annotation instanceof InterceptWith) {
					continue;
				}

				// Extract the aspect class name from the 'value' parameter
				$aspectClass = $annotation->getInterceptClass();

				// Validate the passed class
				if (!class_exists($aspectClass)) {
					throw new \RuntimeException(sprintf(
						'Invalid @InterceptWith target: class "%s" does not exist.',
						$aspectClass
					));
				}

				// Get all annotation parameters except 'value' and 'priority' to pass to aspect constructor
				// For @InterceptWith(CacheAspect::class, ttl=300, priority=10), this gives us ['ttl' => 300]
				$parameters = array_filter($annotation->getParameters(), function ($key) {
					return $key !== 'value' && $key !== 'priority';
				}, ARRAY_FILTER_USE_KEY);

				// Add the aspect class, parameters, and priority to the result list
				$aspects[] = [
					'class'      => $aspectClass,
					'parameters' => $parameters,
					'priority'   => $annotation->getPriority()
				];
			}

			return $aspects;
		}

		/**
		 * Get the full inheritance chain for a class (from parent to child)
		 * @param class-string|object $class
		 * @return array<int, class-string> Array of class names from parent to child
		 */
		protected function getInheritanceChain(string|object $class): array {
			// Validate the class
			if (is_string($class) && !class_exists($class)) {
				return [];
			}

			try {
				$chain = [];
				$current = new \ReflectionClass($class);

				// Walk up the inheritance chain
				while ($current !== false) {
					$chain[] = $current->getName();
					$current = $current->getParentClass();
				}

				// Reverse to get parent-to-child order
				return array_reverse($chain);
			} catch (\ReflectionException $e) {
				return [];
			}
		}
	}