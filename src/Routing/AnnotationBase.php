<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\RoutePrefix;
	
	class AnnotationBase {
		
		/**
		 * AnnotationReader class
		 */
		protected AnnotationReader $annotationsReader;
		
		/**
		 * AnnotationBase constructor
		 * @param AnnotationReader $annotationReader
		 */
		public function __construct(AnnotationReader $annotationReader) {
			$this->annotationsReader = $annotationReader;
		}
		
		/**
		 * Retrieves the route prefix annotation from a given class
		 * @param string|object $class The class object to examine for route prefix annotations
		 * @return string The route prefix string, or empty string if no prefix is found
		 * @throws AnnotationReaderException
		 */
		protected function getRoutePrefix(string|object $class): string {
			// This variable holds all sections
			$result = [];
			
			// Fetch the inheritance chain
			$inheritanceChain = $this->getInheritanceChain($class);
			
			// Walk through the chain and add all route prefixes
			foreach ($inheritanceChain as $controllerName) {
				// Use the annotations reader to search for RoutePrefix annotations on the class
				// This returns an AnnotationCollection of all RoutePrefix annotations found on the class
				$annotations = $this->annotationsReader->getClassAnnotations($controllerName, RoutePrefix::class);
				
				// Skip if no prefix was found
				if ($annotations->isEmpty()) {
					continue;
				}
				
				// Add prefix to the list
				$routePrefix = $annotations[0]->getRoutePrefix();
				
				// Only add prefix if it's not empty
				if ($routePrefix !== '') {
					$result[] = $routePrefix;
				}
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
	
