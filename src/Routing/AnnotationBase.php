<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\RoutePrefix;
	use Quellabs\Canvas\Kernel;
	
	class AnnotationBase {

		use NormalizesRoutes;

		/**
		 * Kernel class
		 */
		protected Kernel $kernel;

		/**
		 * AnnotationReader class
		 */
		protected AnnotationReader $annotationsReader;
		
		/**
		 * AnnotationBase constructor
		 * @param Kernel $kernel
		 */
		public function __construct(Kernel $kernel) {
			$this->kernel = $kernel;
			$this->annotationsReader = $kernel->getAnnotationsReader();
		}
		
		/**
		 * Retrieves the route prefix annotation from a given class
		 * @param class-string|object $class The class object to examine for route prefix annotations
		 * @return string The route prefix string, or empty string if no prefix is found
		 * @throws AnnotationReaderException
		 */
		protected function getRoutePrefix(string|object $class): string {
			// Validate passed class
			if (is_string($class) && !class_exists($class)) {
				return "";
			}
			
			// Fetch the inheritance chain
			$inheritanceChain = $this->getInheritanceChain($class);
			
			// Walk through the chain and add all route prefixes
			$result = [];

			foreach ($inheritanceChain as $controllerName) {
				// Use the annotations reader to search for RoutePrefix annotations on the class
				// This returns an AnnotationCollection of all RoutePrefix annotations found on the class
				$annotations = $this->annotationsReader->getClassAnnotations($controllerName, RoutePrefix::class);
				
				// Skip if no prefix was found
				if ($annotations->isEmpty()) {
					continue;
				}
				
				// Extract first annotation
				$annotation = $annotations[0];
				
				// Continue if this is not a RoutePrefix
				// getClassAnnotations actually mandates only RoutePrefix objects, but phpstan is not happy
				if (!$annotation instanceof RoutePrefix) {
					continue;
				}
				
				// Add prefix to the list
				$routePrefix = $annotation->getRoutePrefix();
				
				// Check that prefix is not empty
				if ($routePrefix === '') {
					continue;
				}
				
				// Add prefix
				$result[] = $routePrefix;
			}

			// If no route prefixes were found, return an empty string
			if (empty($result)) {
				return "";
			}
			
			// Return the result
			return implode("/", $result) . "/";
		}

		/**
		 * Get the full inheritance chain for a class (from parent to child)
		 * @param class-string|object $class
		 * @return array<int, class-string> Array of class names from parent to child
		 */
		protected function getInheritanceChain(string|object $class): array {
			try {
				// Validate class
				if (is_string($class) && !class_exists($class)) {
					return [];
				}
				
				// Create reflection class
				$current = new \ReflectionClass($class);
				
				// Walk up the inheritance chain
				$chain = [];
				
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