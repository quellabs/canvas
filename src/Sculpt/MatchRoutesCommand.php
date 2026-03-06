<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\AnnotationResolver;
	use Quellabs\Sculpt\ConfigurationManager;
	use Symfony\Component\HttpFoundation\Request;
	
	class MatchRoutesCommand extends RoutesBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "route:match";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "Test which route matches a given URL/path";
		}
		
		/**
		 * List the routes
		 * @param ConfigurationManager $config
		 * @return int
		 */
		public function execute(ConfigurationManager $config): int {
			$request = $this->createRequestFromConfig($config);
			
			if ($request === null) {
				return 1;
			}
			
			$kernel = new Kernel();
			$urlResolver = new AnnotationResolver($kernel);
			$routes = $urlResolver->resolveAll($request);
			
			// Extend routes with AOP information
			foreach ($routes as &$route) {
				$route['aspects'] = $this->lister->getAspectsOfMethod($route['controller'], $route['method']);
			}
			
			// Transform route data into table format for display
			$tableData = array_map(function (array $entry) {
				return [
					implode(", ", $entry["http_methods"]),
					"/" . ltrim($entry['route']->getRoute(), '/'),
					$entry['controller'] . "@" . $entry['method'],
					"[" . implode(", ", $entry['aspects']) . "]",
				];
			}, $routes);
			
			$this->getOutput()->table(['HTTP methods', 'Route', 'Controller', 'Aspects'], $tableData);
			
			return 0;
		}
		
		/**
		 * Create a Request object from configuration parameters
		 * @param ConfigurationManager $config
		 * @return Request|null Returns null if validation fails
		 */
		private function createRequestFromConfig(ConfigurationManager $config): ?Request {
			$firstParam = $config->getPositional(0);
			
			if (empty($firstParam)) {
				$this->output->error("Path parameter is required");
				return null;
			}
			
			// List of all http methods
			$httpMethods = ['GET', 'POST', 'DELETE', 'PUT', 'PATCH'];
			
			// First parameter is HTTP method, second is the path
			if (in_array(strtoupper($firstParam), $httpMethods, true)) {
				$path = $config->getPositional(1);
				
				if (empty($path)) {
					$this->output->error("Path parameter is required when HTTP method is specified");
					return null;
				}
				
				return Request::create($path, strtoupper($firstParam));
			}
			
			// First parameter is the path, default to GET
			return Request::create($firstParam);
		}
	}