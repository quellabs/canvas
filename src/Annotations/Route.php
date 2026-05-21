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
		 * @var array<string, mixed>
		 */
		private array $parameters;
		
		/** @var string The aspect class to use for this interception */
		private string $routeName;
		
		/** @var list<string> The http methods */
		private array $methods;
		
		/** @var string|null Fallback route when dynamic route is empty */
		private ?string $fallback;
		
		/**
		 * Route constructor.
		 * @param array<string, mixed> $parameters An associative array of route configuration parameters
		 */
		public function __construct(array $parameters) {
			$value = $parameters['value'];
			$methods = $parameters['methods'];
			$fallback = $parameters['fallback'];
			
			if (!isset($value) || !is_string($value)) {
				throw new \InvalidArgumentException("Route needs a valid route string");
			}
			
			if (isset($fallback) && !is_string($fallback)) {
				throw new \InvalidArgumentException("Invalid fallback. Needs to be a string");
			}
			
			$this->parameters = $parameters;
			$this->routeName = $value;
			$this->methods = $this->parseHttpMethods($parameters['methods'] ?? null);
			$this->fallback = $fallback ?? null;
		}
		
		/**
		 * Returns all route parameters
		 * @return array<string, mixed> The complete array of route parameters
		 */
		public function getParameters(): array {
			return $this->parameters;
		}
		
		/**
		 * Fetches the route path
		 * @return string The route path as defined in the "value" parameter
		 */
		public function getRoute(): string {
			// Fetch unnamed route parameter
			$route = $this->routeName;
			
			// Only run parse_url for full URLs (http/https) to strip scheme and host.
			// Config references (e.g. "mollie::redirectUrl") and plain paths are returned as-is.
			if (str_starts_with($route, 'http://') || str_starts_with($route, 'https://')) {
				$path = parse_url($route, PHP_URL_PATH);
				
				if ($path !== null && $path !== false) {
					return $path;
				}
			}
			
			// Return result
			return $route;
		}
		
		/**
		 * Gets the HTTP methods allowed for this route
		 * @return list<string> List of allowed HTTP methods
		 */
		public function getMethods(): array {
			return $this->methods;
		}
		
		/**
		 * Fetches the route name
		 * @return string|null The name of the route
		 */
		public function getName(): ?string {
			return $this->routeName;
		}
		
		/**
		 * Fetches the fallback route
		 * @return string|null
		 */
		public function getFallback(): ?string {
			return $this->fallback;
		}
		
		/**
		 * Validates and normalizes an array of HTTP methods.
		 * @param mixed $methods
		 * @return list<string>
		 */
		private function parseHttpMethods(mixed $methods): array {
			// No methods specified, default to GET and HEAD
			if (!isset($methods)) {
				return ["GET", "HEAD"];
			}
			
			// Methods must be an array, not a scalar
			if (!is_array($methods)) {
				throw new \InvalidArgumentException("Invalid route methods. Needs to be an array");
			}
			
			// Build a validated list<string> by checking each element individually.
			// array_filter/array_values cannot be used here because PHPStan cannot
			// narrow the value type through a callback, leaving the result as list<mixed>.
			$result = [];
			
			foreach ($methods as $method) {
				if (!is_string($method)) {
					throw new \InvalidArgumentException("Invalid route methods. Each method must be a string");
				}
				
				$result[] = $method;
			}
			
			// Fall back to defaults if the array was empty
			return !empty($result) ? $result : ["GET", "HEAD"];
		}
	}