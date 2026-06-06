<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\ConfigurationManager;
	
	/**
	 * ListRoutesCommand - List all registered application routes
	 *
	 * Displays a formatted table of every route known to the application,
	 * showing the HTTP methods, path, controller action, and any attached aspects.
	 */
	class ListRoutesCommand extends RoutesBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "routes:list";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "List all registered application routes";
		}
		
		/**
		 * Returns extended help text displayed when --help is passed.
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Displays a formatted table of all routes registered in the application,
    including their HTTP methods, path, controller action, and attached aspects.

USAGE:
    php sculpt routes:list

EXAMPLES:
    php sculpt routes:list
        Prints all registered routes to the console

NOTES:
    - Routes are discovered from controller annotations at runtime
    - Aspects are shown as a comma-separated list in brackets
HELP;
		}
		
		/**
		 * List the routes
		 * @param ConfigurationManager $config
		 * @return int
		 */
		public function execute(ConfigurationManager $config): int {
			// Get all registered routes from the application
			$routes = $this->getRoutes($config);
			
			// Transform route data into table format for display
			$tableData = array_map(function (array $entry) {
				return [
					// HTTP method
					implode(", ", $entry["http_methods"]),
					
					// Format route path
					$entry['route'],
					
					// Format controller as ClassName@methodName
					$entry['controller'] . "@" . $entry['method'],
					
					// Format aspects a comma-separated list in brackets
					"[" . implode(",", $entry['aspects']) . "]",
				];
			}, $routes);
			
			// Display routes in a formatted table with headers
			$this->getOutput()->table(['HTTP methods', 'Route', 'Controller', 'Aspects'], $tableData);
			
			// Return success status
			return 0;
		}
	}