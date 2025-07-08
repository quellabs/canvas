<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	
	/**
	 * @Annotation
	 *
	 * Route annotation class for handling HTTP routing.
	 * This class defines a route annotation that can be used to configure
	 * HTTP routes for controller methods.
	 *
	 * Example usage:
	 * @Route("/api/users", methods={"GET"})
	 * @Route("/api/users/{id}", methods="GET")
	 */
	class Route implements AnnotationInterface {
		/**
		 * Array of route parameters including route path and HTTP methods
		 * @var array
		 */
		private array $parameters;
		
		/**
		 * Route constructor.
		 * @param array $parameters An associative array of route configuration parameters
		 *                          - "value": The route path (required)
		 *                          - "methods": HTTP methods allowed for this route (optional)
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
		 * Fetches the route path
		 * @return string The route path as defined in the "value" parameter
		 * @throws \Exception If the "value" parameter is not set (implicit)
		 */
		public function getRoute(): string {
			return $this->parameters["value"];
		}
		
		/**
		 * Gets the HTTP methods allowed for this route
		 * @return array List of allowed HTTP methods
		 *               If not specified, defaults to GET
		 *               If specified as a string, converts to a single-element array
		 */
		public function getMethods(): array {
			// If no methods specified, default to GET
			if (empty($this->parameters["methods"])) {
				return ["GET"];
			}
			
			// If methods is already an array, return it as is
			if (is_array($this->parameters["methods"])) {
				return $this->parameters["methods"];
			}
			
			// If methods is a string, convert to a single-element array
			return [$this->parameters["methods"]];
		}
		
		/**
		 * Fetches the route name
		 * @return string|null The name of the route
		 */
		public function getName(): ?string {
			return $this->parameters["name"] ?? null;
		}
	}