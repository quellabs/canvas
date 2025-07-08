<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Configuration;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\Route;
	use Quellabs\Canvas\AOP\AspectResolver;
	use Quellabs\Discover\Discover;
	use Quellabs\Sculpt\ConfigurationManager;
	
	class AnnotationLister extends AnnotationBase {
		
		/**
		 * Cache for repeated route fetching
		 */
		private ?array $cache = null;
		
		/**
		 * Cache for route name lookups to avoid repeated searches
		 */
		private array $routeNameCache = [];
		
		/**
		 * AnnotationLister constructor
		 */
		public function __construct() {
			$annotationsReaderConfig = new Configuration();
			parent::__construct(new AnnotationReader($annotationsReaderConfig));
		}
		
		/**
		 * Discovers and builds a complete list of all routes in the application
		 * by scanning controller classes and their annotated methods
		 * @return array Array of route configurations with controller, method, route, and aspects info
		 * @throws \ReflectionException
		 * @throws AnnotationReaderException
		 */
		public function getRoutes(?ConfigurationManager $config = null): array {
			// Get from cache if possible
			if (is_array($this->cache)) {
				return $this->cache;
			}
			
			// Initialize the class discovery utility
			$discover = new Discover();
			
			// Scan the Controller directory to find all controller classes
			// This assumes controllers are located in /src/Controller relative to project root
			$controllers = $discover->findClassesInDirectory($discover->getProjectRoot() . "/src/Controllers");
			
			// Iterate through each discovered controller class
			$result = [];
			
			foreach ($controllers as $controller) {
				// Create a reflection object to inspect the controller class structure
				$classReflection = new \ReflectionClass($controller);
				
				// Fetch the route prefix, if any
				$routePrefix = $this->getRoutePrefix($controller);
				
				// Examine each method in the current controller
				foreach ($classReflection->getMethods() as $method) {
					// Look for Route annotations on this method
					// Only methods with Route annotations are considered route handlers
					$routes = $this->annotationsReader->getMethodAnnotations(
						$method->getDeclaringClass()->getName(),
						$method->getName(),
						Route::class
					);
					
					// A single method can have multiple Route annotations (multiple routes to same handler)
					foreach ($routes as $routeAnnotation) {
						// Extract the route path pattern (e.g., "/users/{id}", "/api/products")
						$routePath = $routeAnnotation->getRoute();
						
						// Combine route with prefix
						$completeRoutePath = "/" . $routePrefix . ltrim($routePath, "/");
						
						// Create the record
						$record = [
							'name'         => $routeAnnotation->getName(),    // The name of the route (can be null)
							'http_methods' => $routeAnnotation->getMethods(), // A list of http methods
							'controller'   => $controller,                    // Controller class name
							'method'       => $method->getName(),             // Method name that handles this route
							'route'        => $completeRoutePath,             // Route string
							'aspects'      => $this->getAspectsOfMethod(      // Any interceptors/middleware for this method
								$method->getDeclaringClass()->getName(),
								$method->getName()
							),
						];
						
						// Add to named cache
						if ($routeAnnotation->getName() !== null) {
							$this->routeNameCache[$routeAnnotation->getName()] = $record;
						}
						
						// Build complete route configuration including metadata
						$result[] = $record;
					}
				}
			}
			
			// Sort routes by route first, controller name second, third by method name
			// This makes the route list more predictable and easier to debug
			usort($result, function ($a, $b) {
				// Primary sort: by route
				$routeComparison = $a['route'] <=> $b['route'];
				
				if ($routeComparison !== 0) {
					return $routeComparison;
				}
				
				// Secondary sort: by controller
				$controllerComparison = $a['controller'] <=> $b['controller'];
				
				if ($controllerComparison !== 0) {
					return $controllerComparison;
				}
				
				// Tertiary sort: by method
				return $a['method'] <=> $b['method'];
			});
			
			// Store the list in cache
			$this->cache = $result;
			
			// Filter the routes if needed, then cache and return
			return $config ? $this->filterRoutes($result, $config) : $result;
		}
		
		/**
		 * Check if a route with the given name exists in the route collection.
		 * Uses the pre-built route name cache for O(1) lookup performance.
		 * @param string $name The name of the route to search for
		 * @return bool True if the route exists, false otherwise
		 */
		public function routeExists(string $name): bool {
			try {
				// Ensure routes are discovered and the cache is populated
				$this->getRoutes();
				
				// Use the name cache built during route discovery for instant lookup
				return isset($this->routeNameCache[$name]);
			} catch (AnnotationReaderException | \ReflectionException $e) {
				return false;
			}
		}
		
		/**
		 * Retrieve a route by its name from the route collection.
		 * Uses the pre-built route name cache for O(1) lookup performance.
		 * @param string $name The name of the route to retrieve
		 * @return array|null The route array if found, null if not found
		 */
		public function getRouteByName(string $name): ?array {
			// Ensure routes are discovered and the cache is populated
			try {
				$this->getRoutes();
				
				// Return route from name cache (null if not found)
				return $this->routeNameCache[$name] ?? null;
			} catch (AnnotationReaderException | \ReflectionException $e) {
				return null;
			}
		}
		
		/**
		 * Retrieves all aspect interceptors (middleware/filters) applied to a specific method
		 * @param string $class The fully qualified class name to inspect
		 * @param string $method The method name to check for aspects
		 * @return array Array of interceptor class names ordered by precedence (class-level first, then method-level)
		 */
		public function getAspectsOfMethod(string $class, string $method): array {
			// Initialize the aspect discovery utility
			$aspectResolver = new AspectResolver($this->annotationsReader);
			
			// Fetch all annotation classes in order
			$aspectsClass = $aspectResolver->resolve($class, $method);
			
			// Extract the actual interceptor class names
			return array_map(function ($e) { return $e['class']; }, $aspectsClass);
		}

		/**
		 * Filter routes based on configuration options
		 * @param array $routes Collection of routes to filter
		 * @param ConfigurationManager $config Configuration manager containing filter options
		 * @return array Filtered routes array
		 */
		protected function filterRoutes(array $routes, ConfigurationManager $config): array {
			// Get the controller filter option from configuration
			$controllerFilter = $config->get("controller");
			
			// Apply controller filter if specified
			if ($controllerFilter) {
				// Filter routes by controller name
				$routes = array_filter($routes, function ($route) use ($controllerFilter) {
					return str_contains(strtolower($route['controller']), strtolower($controllerFilter));
				});
			}
			
			// Return the filtered routes (or original routes if no filter applied)
			return $routes;
		}
	}