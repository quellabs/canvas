<?php
	
	namespace Quellabs\Canvas\AOP;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Collection\AnnotationCollection;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\InterceptWith;
	
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
		 * @param object|string $controller The controller instance
		 * @param string $method The method name being called
		 * @return array Array of aspect definitions sorted by inheritance hierarchy and priority
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
				
				// Add to result, maintaining parent-to-child order
				$allAspects = array_merge($allAspects, $aspects);
			}
			
			// Get method-level annotations
			$methodAnnotations = $this->annotationReader->getMethodAnnotations($controller, $method, InterceptWith::class);
			
			// Convert the annotations to aspects
			$methodAspects = $this->convertAnnotationsToAspects($methodAnnotations);
			
			// Sort method aspects by priority
			usort($methodAspects, fn($a, $b) => $b['priority'] <=> $a['priority']);
			
			// Combine: all class-level aspects (parent to child) → method aspects
			return array_merge($allAspects, $methodAspects);
		}
		
		/**
		 * Convert annotation instances to aspect definitions with parameters and priority
		 * @param AnnotationCollection $annotations Collection of InterceptWith annotations
		 * @return array Array of aspect definitions
		 */
		private function convertAnnotationsToAspects(AnnotationCollection $annotations): array {
			$aspects = [];
			
			foreach ($annotations as $annotation) {
				// Extract the aspect class name from the 'value' parameter
				$aspectClass = $annotation->getInterceptClass();
				
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
		 * @param string|object $class
		 * @return array Array of class names from parent to child
		 */
		protected function getInheritanceChain(string|object $class): array {
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