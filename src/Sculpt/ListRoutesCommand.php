<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\ConfigurationManager;
	
	class ListRoutesCommand extends RoutesBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "route:list";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "List routes";
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