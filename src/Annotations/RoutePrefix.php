<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * RoutePrefix Annotation Class
	 *
	 * This class implements an annotation interface for defining route prefixes
	 * in a routing system. It stores and provides access to route configuration
	 * parameters such as the route path and allowed HTTP methods.
	 *
	 * Used as an annotation to define route prefixes for controllers or methods
	 * in a web application routing system.
	 */
	class RoutePrefix implements AnnotationInterface {
		
		/**
		 * Array of route parameters including route path and HTTP methods
		 * @var array
		 */
		private array $parameters;
		
		/**
		 * Initializes the RoutePrefix annotation with the provided parameters.
		 * The parameter array should contain at minimum a "value" key with the route path.
		 * @param array $parameters An associative array of route configuration parameters
		 */
		public function __construct(array $parameters) {
			$this->parameters = $parameters;
		}
		
		/**
		 * Returns all route parameters
		 * @return array The complete array of route parameters
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Fetches the route prefix
		 * @return string The route prefix
		 */
		public function getRoutePrefix(): string {
			return trim($this->parameters["value"], '/ ');
		}
	}