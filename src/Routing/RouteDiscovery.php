<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\Canvas\Annotations\RoutePrefix;
	use ReflectionException;
	use Quellabs\Canvas\Annotations\Route;
	use Quellabs\Canvas\Kernel;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	
	/**
	 * Discovers and extracts routes from controller classes using reflection and
	 * annotation reading. This class handles the scanning of controller directories,
	 * extraction of route annotations, and building of complete route definitions
	 * with compiled patterns and calculated priorities.
	 */
	class RouteDiscovery {
		
		private Kernel $kernel;
		private RouteSegmentAnalyzer $segmentAnalyzer;
		private RoutePatternCompiler $patternCompiler;
		
		/** @var array Cache for reflection results to avoid repeated reflection operations */
		private array $reflectionCache = [];
		
		/**
		 * RouteDiscovery constructor
		 * @param Kernel $kernel
		 * @param RouteSegmentAnalyzer $segmentAnalyzer
		 * @param RoutePatternCompiler $patternCompiler
		 */
		public function __construct(
			Kernel               $kernel,
			RouteSegmentAnalyzer $segmentAnalyzer,
			RoutePatternCompiler $patternCompiler
		) {
			$this->kernel = $kernel;
			$this->segmentAnalyzer = $segmentAnalyzer;
			$this->patternCompiler = $patternCompiler;
		}
		
		/**
		 * This method discovers all controller classes in the controller directory,
		 * extracts their route definitions, and pre-compiles the route patterns
		 * for optimal runtime performance. The compiled routes are sorted by
		 * priority to ensure correct matching order during request processing.
		 *
		 * NOTE: This is an expensive operation that should only be called when the
		 * route cache needs to be rebuilt.
		 *
		 * @return array Array of compiled route definitions sorted by priority (highest first)
		 */
		public function buildRoutesFromControllers(): array {
			// Fetch the controller directory
			$controllerDir = $this->getControllerDirectory();
			
			if (!$controllerDir) {
				return [];
			}
			
			// Discover and process all controller classes in the directory
			$result = [];

			foreach ($this->kernel->getDiscover()->findClassesInDirectory($controllerDir) as $controller) {
				// Extract route definitions from the current controller
				$controllerRoutes = $this->getRoutesFromController($controller);
				
				// Pre-compile route patterns for performance optimization
				foreach ($controllerRoutes as &$route) {
					// Store the compiled pattern alongside the original route data
					$route['compiled_pattern'] = $this->patternCompiler->preCompileRoute($route['route_path']);
				}
				
				// Merge the processed routes from this controller into the main result
				$result = array_merge($result, $controllerRoutes);
			}
			
			// Sort all routes by priority (highest priority first)
			usort($result, fn($a, $b) => $b['priority'] <=> $a['priority']);
			
			// Return result
			return $result;
		}
		
		/**
		 * Gets all potential routes from a controller with their priorities
		 *
		 * This method extracts route definitions from a controller class by combining
		 * the controller's route prefix with individual method route annotations.
		 * Each route is assigned a priority based on its specificity to ensure
		 * proper matching order during request processing.
		 *
		 * @param string $controller The fully qualified controller class name
		 * @return array Array of route definitions with complete metadata
		 * @throws AnnotationReaderException When annotation reading fails
		 */
		public function getRoutesFromController(string $controller): array {
			$routes = [];
			
			try {
				// Get the route prefix for this controller (e.g., from class-level Route annotation)
				$routePrefix = $this->getRoutePrefix($controller);
				
				// Extract all route annotations from public methods in this controller
				$routeAnnotations = $this->getMethodRouteAnnotations($controller);
				
				// Process each method's route annotation to create complete route definitions
				foreach ($routeAnnotations as $method => $routeAnnotation) {
					// Get the method-specific route path from the annotation
					$routePath = $routeAnnotation->getRoute();
					
					// Combine controller prefix with method route to create complete path
					$completeRoutePath = $this->buildCompleteRoutePath($routePrefix, $routePath);
					
					// Calculate priority based on route specificity
					$priority = $this->segmentAnalyzer->calculateRoutePriority($completeRoutePath);
					
					// Build complete route definition with all necessary metadata
					$routes[] = [
						'http_methods' => $routeAnnotation->getMethods(),
						'controller'   => $controller,
						'method'       => $method,
						'route'        => $routeAnnotation,
						'route_path'   => $completeRoutePath,
						'priority'     => $priority
					];
				}
			} catch (AnnotationReaderException $e) {
				// Log error but don't stop the discovery process
				error_log("RouteDiscovery: Error processing controller {$controller}: " . $e->getMessage());
			}
			
			return $routes;
		}
		
		/**
		 * Get all controllers in the controller directory
		 * @return array Array of fully qualified controller class names
		 */
		public function getAllControllers(): array {
			$controllerDir = $this->getControllerDirectory();
			
			if (!$controllerDir) {
				return [];
			}
			
			return $this->kernel->getDiscover()->findClassesInDirectory($controllerDir);
		}
		
		/**
		 * Get route statistics from discovered controllers
		 * @return array Associative array with discovery statistics
		 * @throws AnnotationReaderException
		 */
		public function getDiscoveryStatistics(): array {
			// Get all discovered controller classes from the configured directory
			$controllers = $this->getAllControllers();
			
			// Initialize counters for statistical calculations
			$totalRoutes = 0;                    // Total number of routes across all controllers
			$controllersWithRoutes = 0;          // Count of controllers that have at least one route
			$routesByController = [];            // Map of controller class name to route count
			
			// Process each controller to extract route information
			foreach ($controllers as $controller) {
				// Extract routes from the current controller using annotation parsing
				// This may throw AnnotationReaderException if annotations are malformed
				$routes = $this->getRoutesFromController($controller);
				
				// Count the number of routes found in this controller
				$routeCount = count($routes);
				
				// Track controllers that actually define routes (not empty controllers)
				if ($routeCount > 0) {
					$controllersWithRoutes++;
				}
				
				// Accumulate total route count across all controllers
				$totalRoutes += $routeCount;
				
				// Store per-controller route count for detailed breakdown
				$routesByController[$controller] = $routeCount;
			}
			
			return [
				// Basic counts
				'total_controllers'             => count($controllers),
				'controllers_with_routes'       => $controllersWithRoutes,
				'total_routes'                  => $totalRoutes,
				
				// Calculated average with protection against division by zero
				// Rounds to 2 decimal places for readability
				'average_routes_per_controller' => count($controllers) > 0 ? round($totalRoutes / count($controllers), 2) : 0,
				
				// Detailed breakdown showing route count per controller class
				'routes_by_controller'          => $routesByController,
				
				// Context information about where controllers were discovered
				'controller_directory'          => $this->getControllerDirectory()
			];
		}
		
		/**
		 * Get route prefix from controller class annotation
		 * @param string $controller Fully qualified controller class name
		 * @return string Route prefix (without leading slash)
		 */
		public function getRoutePrefix(string $controller): string {
			try {
				// Get class-level Route annotations
				$classAnnotations = $this->kernel->getAnnotationsReader()->getClassAnnotations($controller, RoutePrefix::class);
				
				// Use the first Route annotation found as the prefix
				if (!$classAnnotations->isEmpty()) {
					$routeAnnotation = $classAnnotations[0];
					return ltrim($routeAnnotation->getRoute(), '/');
				}
			} catch (AnnotationReaderException $e) {
				// Log error but continue with empty prefix
				error_log("RouteDiscovery: Error reading class annotations for {$controller}: " . $e->getMessage());
			}
			
			return '';
		}
		
		/**
		 * Clear the reflection cache
		 * @return void
		 */
		public function clearReflectionCache(): void {
			$this->reflectionCache = [];
		}
		
		/**
		 * This method uses reflection to scan controller classes and extract route
		 * annotations from public methods. The results are cached in memory to avoid
		 * repeated expensive reflection operations during route building.
		 * @param object|string $controller Controller instance or class name to scan
		 * @return array Associative array mapping method names to their Route annotations
		 * @throws AnnotationReaderException When annotation reading fails
		 */
		private function getMethodRouteAnnotations(object|string $controller): array {
			// Normalize controller to class name for consistent caching
			$className = is_string($controller) ? $controller : get_class($controller);
			
			// Check if we've already processed this controller class
			if (isset($this->reflectionCache[$className])) {
				return $this->reflectionCache[$className];
			}
			
			try {
				// Create reflection class to analyze the controller
				$reflectionClass = new \ReflectionClass($className);
				
				// Get all public methods - these are potential route handlers
				$methods = $reflectionClass->getMethods(\ReflectionMethod::IS_PUBLIC);
				
				// Scan each public method for Route annotations
				$result = [];

				foreach ($methods as $method) {
					// Skip magic methods and constructor
					if ($this->shouldSkipMethod($method->getName())) {
						continue;
					}
					
					// Use the annotations reader to extract Route annotations from this method
					$annotations = $this->kernel->getAnnotationsReader()->getMethodAnnotations(
						$controller,
						$method->getName(),
						Route::class
					);
					
					// Process each Route annotation found on this method
					foreach ($annotations as $annotation) {
						$result[$method->getName()] = $annotation;
						break; // Only use the first route annotation per method
					}
				}
				
				// Cache the results and return
				return $this->reflectionCache[$className] = $result;
				
			} catch (ReflectionException $e) {
				throw new AnnotationReaderException(
					"Failed to reflect controller class {$className}: " . $e->getMessage(),
					0,
					$e
				);
			}
		}
		
		/**
		 * Build a complete route path by combining prefix and method route
		 * @param string $prefix Controller route prefix
		 * @param string $routePath Method route path
		 * @return string Complete route path
		 */
		private function buildCompleteRoutePath(string $prefix, string $routePath): string {
			// Handle root route case
			if ($routePath === '/') {
				return $prefix ? "/{$prefix}" : '/';
			}
			
			// Combine prefix and route path, handling slashes properly
			$prefix = trim($prefix, '/');
			$routePath = ltrim($routePath, '/');
			
			if ($prefix) {
				return "/{$prefix}/{$routePath}";
			}
			
			return "/{$routePath}";
		}
		
		/**
		 * Check if a method should be skipped during route discovery
		 * @param string $methodName Method name to check
		 * @return bool True if method should be skipped
		 */
		private function shouldSkipMethod(string $methodName): bool {
			// Skip magic methods, constructor, and common framework methods
			$skipMethods = [
				'__construct',
				'__destruct',
				'__call',
				'__callStatic',
				'__get',
				'__set',
				'__isset',
				'__unset',
				'__sleep',
				'__wakeup',
				'__toString',
				'__invoke',
				'__set_state',
				'__clone',
				'__debugInfo'
			];
			
			return in_array($methodName, $skipMethods) || str_starts_with($methodName, '__');
		}
		
		/**
		 * Gets the absolute path to the controllers directory
		 * @return string|null Absolute path to controllers directory or null if not found
		 */
		private function getControllerDirectory(): ?string {
			$projectRoot = $this->kernel->getDiscover()->getProjectRoot();
			$fullPath = $projectRoot . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "Controllers";
			
			if (!is_dir($fullPath)) {
				return null;
			}
			
			return realpath($fullPath);
		}
	}