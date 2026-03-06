<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\Canvas\Annotations\RoutePrefix;
	use Quellabs\Support\ComposerUtils;
	use ReflectionException;
	use Quellabs\Canvas\Annotations\Route;
	use Quellabs\Canvas\Kernel;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	
	/**
	 * RouteDiscovery
	 *
	 * Discovers and extracts routes from controller classes using reflection and
	 * annotation reading. Handles the scanning of controller directories, extraction
	 * of route annotations, and building of complete route definitions with compiled
	 * patterns and calculated priorities.
	 *
	 * Core responsibilities:
	 * - Controller class discovery: Recursively scans configured controller directories
	 * - Annotation extraction: Uses reflection to read @Route and @RoutePrefix annotations
	 * - Route compilation: Pre-compiles route patterns using RoutePatternCompiler
	 * - Priority calculation: Assigns priority scores based on route specificity
	 * - Route prefix handling: Combines class-level prefixes with method-level routes
	 * - Inheritance support: Walks class inheritance chains for route prefix accumulation
	 *
	 * Discovery process:
	 * 1. Scans controller directory for PHP classes
	 * 2. Reflects each controller class to examine public methods
	 * 3. Extracts @RoutePrefix annotations from class hierarchy
	 * 4. Finds @Route annotations on individual methods
	 * 5. Combines prefixes with method routes to build complete paths
	 * 6. Compiles route patterns for optimal runtime matching
	 * 7. Calculates priority scores for proper matching order
	 * 8. Sorts routes by priority (highest specificity first)
	 *
	 * Route priority calculation considers:
	 * - Static segments (higher priority)
	 * - Variable segments (medium priority)
	 * - Wildcard segments (lower priority)
	 * - Route length (longer routes slightly favored)
	 * - Fully static routes (highest priority bonus)
	 */
	class RouteDiscovery {
		
		private Kernel $kernel;
		private ControllersDiscovery $controllersDiscovery;
		private RouteSegmentAnalyzer $segmentAnalyzer;
		private RoutePatternCompiler $patternCompiler;
		
		/**
		 * RouteDiscovery constructor
		 * @param Kernel $kernel
		 * @param ControllersDiscovery $controllersDiscovery
		 * @param RouteSegmentAnalyzer $segmentAnalyzer
		 * @param RoutePatternCompiler $patternCompiler
		 */
		public function __construct(
			Kernel               $kernel,
			ControllersDiscovery $controllersDiscovery,
			RouteSegmentAnalyzer $segmentAnalyzer,
			RoutePatternCompiler $patternCompiler
		) {
			$this->kernel = $kernel;
			$this->controllersDiscovery = $controllersDiscovery;
			$this->segmentAnalyzer = $segmentAnalyzer;
			$this->patternCompiler = $patternCompiler;
		}
		
		/**
		 * Discovers all controller classes, extracts their route definitions, and
		 * pre-compiles the route patterns for optimal runtime performance. The compiled
		 * routes are sorted by priority to ensure correct matching order during request
		 * processing.
		 * @return array Array of compiled route definitions sorted by priority (highest first)
		 * @throws AnnotationReaderException
		 */
		public function buildRoutesFromControllers(): array {
			$controllerDirectories = $this->controllersDiscovery->fetch();
			
			if (empty($controllerDirectories)) {
				return [];
			}
			
			$result = [];
			
			foreach ($controllerDirectories as $controllerDirectory) {
				foreach (ComposerUtils::findClassesInDirectory($controllerDirectory) as $controller) {
					foreach ($this->getRoutesFromController($controller) as &$route) {
						$route['compiled_pattern'] = $this->patternCompiler->compileRoute($route['route_path']);
						$result[] = $route;
					}
				}
			}
			
			// Sort all routes by priority (highest priority first)
			usort($result, fn($a, $b) => $b['priority'] <=> $a['priority']);
			
			return $result;
		}
		
		/**
		 * Get route prefix from controller class annotation
		 * @param string $controller Fully qualified controller class name
		 * @return string Route prefix (without leading slash)
		 * @throws AnnotationReaderException
		 */
		private function getRoutePrefix(string $controller): string {
			$classAnnotations = $this->kernel->getAnnotationsReader()->getClassAnnotations($controller, RoutePrefix::class);
			
			if ($classAnnotations->isEmpty()) {
				return '';
			}
			
			return ltrim($classAnnotations[0]->getRoutePrefix(), '/');
		}
		
		/**
		 * Extracts route definitions from a controller class by combining the
		 * controller's route prefix with individual method route annotations.
		 * Each route is assigned a priority based on its specificity to ensure
		 * proper matching order during request processing.
		 * @param string $controller The fully qualified controller class name
		 * @return array Array of route definitions with complete metadata
		 * @throws AnnotationReaderException When annotation reading fails
		 */
		private function getRoutesFromController(string $controller): array {
			$routes = [];
			$routePrefix = $this->getRoutePrefix($controller);
			
			foreach ($this->getMethodRouteAnnotations($controller) as $routeData) {
				$routeAnnotation = $routeData['annotation'];
				$completeRoutePath = $this->buildCompleteRoutePath($routePrefix, $routeAnnotation->getRoute());
				
				$routes[] = [
					'http_methods' => $routeAnnotation->getMethods(),
					'controller'   => $controller,
					'method'       => $routeData['method'],
					'route'        => $routeAnnotation,
					'route_path'   => $completeRoutePath,
					'priority'     => $this->segmentAnalyzer->calculateRoutePriority($completeRoutePath)
				];
			}
			
			return $routes;
		}
		
		/**
		 * Uses reflection to scan a controller class and extract Route annotations
		 * from its public non-magic methods.
		 * @param string $controller Controller class name to scan
		 * @return array Array of ['method' => string, 'annotation' => Route] entries
		 * @throws AnnotationReaderException When annotation reading or reflection fails
		 */
		private function getMethodRouteAnnotations(string $controller): array {
			try {
				$reflectionClass = new \ReflectionClass($controller);
				$result = [];
				
				foreach ($reflectionClass->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
					if (str_starts_with($method->getName(), '__')) {
						continue;
					}
					
					foreach ($this->kernel->getAnnotationsReader()->getMethodAnnotations($controller, $method->getName(), Route::class) as $annotation) {
						$result[] = [
							'method'     => $method->getName(),
							'annotation' => $annotation
						];
					}
				}
				
				return $result;
				
			} catch (ReflectionException $e) {
				throw new AnnotationReaderException(
					"Failed to reflect controller class {$controller}: " . $e->getMessage(),
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
			if ($routePath === '/') {
				return $prefix ? "/{$prefix}" : '/';
			}
			
			$prefix = trim($prefix, '/');
			$routePath = ltrim($routePath, '/');
			
			return $prefix ? "/{$prefix}/{$routePath}" : "/{$routePath}";
		}
	}