<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Configuration;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\Route;
	use Quellabs\Canvas\AOP\AspectResolver;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Components\ControllersDiscovery;
	use Quellabs\Canvas\Routing\Components\RouteDiscovery;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Support\ComposerUtils;
	
	class AnnotationLister extends AnnotationBase {
		
		/**
		 * @var Kernel Application kernel
		 */
		private Kernel $kernel;
		
		/**
		 * @var ControllersDiscovery Controller discovery component
		 */
		private ControllersDiscovery $controllersDiscovery;
		
		/**
		 * @var AspectResolver Resolves aspects/interceptors for methods
		 */
		private AspectResolver $aspectResolver;
		
		/**
		 * AnnotationLister constructor
		 */
		public function __construct() {
			$this->kernel = new Kernel();
			parent::__construct($this->kernel->getAnnotationsReader());
			$this->controllersDiscovery = new ControllersDiscovery($this->kernel);
			$this->aspectResolver = new AspectResolver($this->annotationsReader);
		}
		
		/**
		 * Discovers and builds a complete list of all routes in the application
		 * by scanning controller classes and their annotated methods
		 * @return array Array of route configurations with controller, method, route, and aspects info
		 * @throws \ReflectionException
		 * @throws AnnotationReaderException
		 */
		public function getRoutes(?ConfigurationManager $config = null): array {
			$routes = $this->discoverRoutes();
			return $config ? $this->filterRoutes($routes, $config) : $routes;
		}
		
		/**
		 * Discovers all routes by scanning controllers and their annotated methods.
		 * Populates the route name cache as a side effect.
		 * @return array Sorted array of route configurations
		 * @throws \ReflectionException
		 * @throws AnnotationReaderException
		 */
		private function discoverRoutes(): array {
			$result = [];
			
			// Iterate through each discovered controller class
			foreach($this->controllersDiscovery->fetch() as $directory) {
				// Scan the controller directory to find all controller classes
				foreach (ComposerUtils::findClassesInDirectory($directory) as $controller) {
					// Create a reflection object to inspect the controller class structure
					$classReflection = new \ReflectionClass($controller);
					
					// Fetch the route prefix, if any
					$routePrefix = $this->getRoutePrefix($controller);
					
					// Examine each method in the current controller
					foreach ($classReflection->getMethods() as $method) {
						// Look for Route annotations on this method.
						// Only methods with Route annotations are considered route handlers.
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
							
							// Build complete route configuration including metadata
							$result[] = $record;
						}
					}
				}
			}
			
			// Sort routes by route first, controller name second, then by method name.
			// This makes the route list more predictable and easier to debug.
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
			
			return $result;
		}
		
		/**
		 * Retrieve a route by its name from the route collection.
		 * Uses the pre-built route name cache for O(1) lookup performance.
		 * @param string $name The name of the route to retrieve
		 * @return array|null The route array if found, null if not found
		 */
		public function getRouteByName(string $name): ?array {
			try {
				foreach ($this->getRoutes() as $route) {
					if ($route['name'] === $name) {
						return $route;
					}
				}
				
				return null;
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
			// Fetch all annotation classes in order and extract the interceptor class names
			return array_map(
				function ($e) { return $e['class']; },
				$this->aspectResolver->resolve($class, $method)
			);
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