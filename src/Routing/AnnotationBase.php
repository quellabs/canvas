<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\RoutePrefix;
	use Quellabs\Canvas\Kernel;
	
	class AnnotationBase {

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
		
		/**
		 * Normalizes a route string, resolving config file references if present.
		 * Config references use the format "filename::key" (e.g. "mollie::redirectUrl"),
		 * which is resolved by loading the corresponding config file and looking up the key.
		 * Plain route strings (e.g. "/payment/return") are returned as-is.
		 * @param string $route The route string to normalize, either a plain path or a config reference
		 * @param string|null $default Fallback value if the config key is not found
		 * @return string The resolved route path
		 * @throws \RuntimeException If the config key is not found and no default is provided
		 */
		protected function normalizeRoute(string $route, ?string $default = null): string {
			// Plain route path — nothing to resolve
			if (!str_contains($route, "::")) {
				return $route;
			}
			
			// Split "filename::key" into its two components
			$parts = explode("::", $route, 2);
			$file  = $parts[0];
			$key   = $parts[1];
			
			// Load the config file and look up the key, falling back to $default if absent
			$result = $this->kernel->loadConfigFile("{$file}.php")->get($key, $default);
			
			// No value and no default — the annotation references a key that doesn't exist
			if ($result === null) {
				throw new \RuntimeException("Couldn't load route '{$key}' from config file '{$file}'.");
			}
			
			return $result;
		}
	}
	
