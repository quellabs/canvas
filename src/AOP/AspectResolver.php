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
		 * Combines class-level aspects (applied to all methods) with method-level aspects
		 * @param object|string $controller The controller instance
		 * @param string $method The method name being called
		 * @return array Array of aspect annotation instances
		 * @throws AnnotationReaderException
		 */
		public function resolve(object|string $controller, string $method): array {
			// Get all aspect annotations
			$allAnnotations = $this->getAspectAnnotations($controller, $method);

			// Convert annotation instances to actual aspect objects with their parameters
			$aspects = [];
			
			foreach ($allAnnotations as $annotation) {
				// Extract the aspect class name from the 'value' parameter
				// This comes from @InterceptWith(CacheAspect::class, ttl=300)
				$aspectClass = $annotation->getInterceptClass(); // e.g., CacheAspect::class
				
				// Get all annotation parameters except 'value' to pass to aspect constructor
				// For @InterceptWith(CacheAspect::class, ttl=300), this gives us ['ttl' => 300]
				$parameters = array_filter($annotation->getParameters(), function ($key) {
					return $key !== 'value';
				}, ARRAY_FILTER_USE_KEY);
				
				// Add the aspect class and parameters to the result list
				$aspects[] = [
					'class'      => $aspectClass,
					'parameters' => $parameters
				];
			}
			
			return $aspects;
		}
		
		/**
		 * Fetch all AOP Aspects for the method
		 * @param object|string $controller
		 * @param string $method
		 * @return AnnotationCollection
		 * @throws AnnotationReaderException
		 */
		protected function getAspectAnnotations(object|string $controller, string $method): AnnotationCollection {
			// Fetch the inheritance chain of the controller
			$inheritanceChain = $this->getInheritanceChain($controller);
			
			// Get all annotations from the controller class and filter for aspect annotations
			// Class-level aspects apply to all methods in the controller
			$classAnnotations = new AnnotationCollection();
			
			foreach($inheritanceChain as $class) {
				$classAnnotations = $classAnnotations->merge($this->annotationReader->getClassAnnotations($class, InterceptWith::class));
			}
			
			// Get all annotations from the specific method and filter for aspect annotations
			// Method-level aspects only apply to this specific method
			$methodAnnotations = $this->annotationReader->getMethodAnnotations($controller, $method, InterceptWith::class);
			
			// Merge class-level and method-level aspects
			// Class aspects are applied first, then method aspects
			// This allows method-level aspects to override or extend class-level behavior
			return $classAnnotations->merge($methodAnnotations);
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