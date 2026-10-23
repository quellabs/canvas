<?php
	
	namespace Quellabs\Canvas\Annotations;
	
	use Quellabs\AnnotationReader\AnnotationInterface;
	use Quellabs\AnnotationReader\Annotation\UnsuppliedParameter;
	
	/**
	 * @Annotation
	 * @Target("METHOD")
	 *
	 * Route annotation class for handling HTTP routing.
	 * This class defines a route annotation that can be used to configure
	 * HTTP routes for controller methods.
	 *
	 * Example usage:
	 * @Route("/api/users", methods={"GET"})
	 * @Route("/api/users/{id}", methods="GET")
	 */
	#[\Attribute(\Attribute::TARGET_METHOD | \Attribute::IS_REPEATABLE)]
	class Route implements AnnotationInterface {
		private string $value;
		/**
		 * @var list<string> The http methods
		 */
		private array $methods;
		
		/**
		 * @var string|null Fallback route when dynamic route is empty
		 */
		private ?string $fallback;
		
		/**
		 * @var array<string, mixed> Only the keys the caller actually supplied
		 */
		private array $parameters;
		
		/**
		 * Route constructor.
		 * @param string $value Route path
		 * @param array<int, string>|UnsuppliedParameter $methods Allowed HTTP methods
		 * @param string|UnsuppliedParameter|null $fallback Fallback route
		 */
		public function __construct(string $value, array|UnsuppliedParameter $methods = new UnsuppliedParameter(), string|UnsuppliedParameter|null $fallback = new UnsuppliedParameter()) {
			$this->value = $value;
			$this->parameters = ['value' => $value];
			$this->methods = $this->parseHttpMethods($methods instanceof UnsuppliedParameter ? ['GET', 'HEAD'] : $methods);
			
			if (!($methods instanceof UnsuppliedParameter)) {
				$this->parameters['methods'] = $methods;
			}
			
			$this->fallback = $fallback instanceof UnsuppliedParameter ? null : $fallback;
			
			if (!($fallback instanceof UnsuppliedParameter)) {
				$this->parameters['fallback'] = $fallback;
			}
		}
		
		/**
		 * Returns only the route parameters the caller explicitly supplied
		 * @return array<string, mixed>
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
			$route = $this->value;
			
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
			return $this->value;
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
