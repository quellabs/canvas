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
			// Create a request object out of the configuration options
			$request = $this->createRequestFromConfig($config);

			if ($request === null) {
				return 1;
			}
			
			// Fetch a list of matching routes for the given path
			$kernel = new Kernel();
			$urlResolver = new AnnotationResolver($kernel);
			$routes = $urlResolver->resolveAll($request);
			
			// Extend routes with AOP information
			for ($i = 0; $i < count($routes); ++$i) {
				$routes[$i]['aspects'] = $this->lister->getAspectsOfMethod($routes[$i]['controller'], $routes[$i]['method']);
			}
			
			// Transform route data into table format for display
			$tableData = array_map(function (array $entry) {
				return [
					// HTTP method
					implode(", ", $entry["http_methods"]),
					
					// Format route path with leading slash
					"/" . ltrim($entry['route']->getRoute(), '/'),
					
					// Format controller as ClassName@methodName
					$entry['controller'] . "@" . $entry['method'],
					
					// Format aspects as comma-separated list in brackets
					"[" . implode(",", $entry['aspects']) . "]",
				];
			}, $routes);
			
			// Display routes in a formatted table with headers
			$this->getOutput()->table(['HTTP methods', 'Route', 'Controller', 'Aspects'], $tableData);
			
			// Return success status
			return 0;
		}
		
		/**
		 * Create a Request object from configuration parameters
		 * @param ConfigurationManager $config
		 * @return Request|null Returns null if validation fails
		 */
		private function createRequestFromConfig(ConfigurationManager $config): ?Request {
			$firstParam = $config->getPositional(0);

			// Check if path parameter is provided
			if (empty($firstParam)) {
				$this->output->error("Path parameter is required");
				return null;
			}
			
			// First parameter is HTTP method, second should be the path
			if (in_array($firstParam, ['GET', 'POST', 'DELETE', 'PUT', 'PATCH'], true)) {
				$path = $config->getPositional(1);
				
				if (empty($path)) {
					$this->output->error("Path parameter is required when HTTP method is specified");
					return null;
				}
				
				return Request::create($path, $firstParam);
			}
			
			// The first parameter is the path
			return Request::create($firstParam);
		}
	}