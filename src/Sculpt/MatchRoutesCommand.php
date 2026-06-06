<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\AnnotationResolver;
	use Quellabs\Sculpt\ConfigurationManager;
	use Symfony\Component\HttpFoundation\Request;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	
	/**
	 * MatchRoutesCommand - Test which routes match a given URL and HTTP method
	 *
	 * Resolves a path against the application's registered routes and displays
	 * all matches in a table, including the controller action and any attached
	 * aspects. Defaults to GET when no HTTP method is specified.
	 */
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
		 * Returns extended help text displayed when --help is passed.
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Resolves a path against the application's registered routes and displays all
    matches in a table with their HTTP methods, controller action, and aspects.
    When no HTTP method is given, GET is assumed.

USAGE:
    php sculpt route:match <path>
    php sculpt route:match <method> <path>

ARGUMENTS:
    method    HTTP method to match against (GET, POST, PUT, PATCH, DELETE)
              Defaults to GET when omitted
    path      The URL path to match (e.g. /users/42)

EXAMPLES:
    php sculpt route:match /users/42
        Matches /users/42 using GET

    php sculpt route:match POST /users
        Matches /users using POST

NOTES:
    - Aspects are shown as a comma-separated list in brackets
    - An empty result table means no route matched the given path and method
HELP;
		}
		
		/**
		 * List the routes
		 * @param ConfigurationManager $config
		 * @return int
		 * @throws AnnotationReaderException
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