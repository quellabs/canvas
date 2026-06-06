<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * CreateControllerCommand - Create a new controller class
	 *
	 * Generates a controller class in App\Controllers with a basic route-annotated
	 * index action. The controller name can be passed as a positional argument or
	 * entered interactively when omitted.
	 */
	class CreateControllerCommand extends CommandBase {
		
		/**
		 * Returns the signature of this command
		 * @return string The command signature used for CLI invocation
		 */
		public function getSignature(): string {
			return "make:controller";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string Brief description displayed in help output
		 */
		public function getDescription(): string {
			return "Creates a new controller class with basic template structure";
		}
		
		/**
		 * Show help information for publishers
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Generates a controller class in the App\Controllers namespace with a basic
    route-annotated index action. The "Controller" suffix is added automatically
    and stripped from input if already present.

USAGE:
    php sculpt make:controller [controller-name]

ARGUMENTS:
    controller-name    Name of the controller without the "Controller" suffix
                       If omitted, you will be prompted to enter one

EXAMPLES:
    php sculpt make:controller User
        Creates src/Controllers/UserController.php

    php sculpt make:controller
        Prompts for the controller name interactively

NOTES:
    - The "Controller" suffix is stripped from input and re-added automatically
    - Names are converted to PascalCase; hyphens and underscores act as word separators
    - The command exits without error if the controller file already exists
HELP;
		}
		
		/**
		 * Execute the controller creation command
		 * @param ConfigurationManager $config Configuration containing command flags and options
		 * @return int Exit code (0 = success, 1 = error)
		 */
		public function execute(ConfigurationManager $config): int {
			// Get controller name from first positional argument
			if (!empty($config->getPositional(0))) {
				$controllerName = $config->getPositional(0);
			} else {
				$controllerName = $this->input->ask("Controller name");
			}
			
			// Exit gracefully if no name provided
			if (empty($controllerName)) {
				$this->output->writeLn("Controller name is required.");
				return 1;
			}
			
			// Sanitize controller name - ensure it follows proper naming conventions
			$controllerName = $this->sanitizeControllerName($controllerName);
			
			// Build complete file path in project root
			$completePath = ComposerUtils::getProjectRoot() . "/src/Controllers/" . $controllerName . "Controller.php";
			
			// Check if controller already exists to prevent overwriting
			if (file_exists($completePath)) {
				$this->output->writeLn("Controller '{$controllerName}Controller' already exists at: {$completePath}");
				return 0;
			}
			
			// Generate controller content from template
			$controllerContents = $this->createController($controllerName);
			
			// Ensure the target directory exists before writing file
			$this->ensureDirectoryExists($completePath);
			
			// Write the controller file to disk
			if (file_put_contents($completePath, $controllerContents) === false) {
				$this->output->writeLn("Failed to create controller file: {$completePath}");
				return 1;
			}
			
			// Success message
			$this->output->writeLn("Controller '{$controllerName}Controller' created successfully at: {$completePath}");
			
			return 0;
		}
		
		/**
		 * Sanitize the controller name to ensure it follows PHP class naming conventions
		 * @param string $controllerName Raw controller name from user input
		 * @return string Sanitized controller name ready for class generation
		 */
		private function sanitizeControllerName(string $controllerName): string {
			// Remove 'Controller' suffix if user included it
			$controllerName = preg_replace('/Controller$/i', '', trim($controllerName)) ?? $controllerName;;
			
			// Convert to PascalCase - capitalize first letter and after underscores/hyphens
			$controllerName = str_replace(['-', '_'], ' ', $controllerName);
			$controllerName = ucwords($controllerName);
			return str_replace(' ', '', $controllerName);
		}
		
		/**
		 * Generate controller class content from template
		 * @param string $controllerName The sanitized controller name (without 'Controller' suffix)
		 * @return string Complete PHP class content ready to be written to file
		 */
		private function createController(string $controllerName): string {
			$route = strtolower($controllerName);
			
			return <<<PHP
<?php

	namespace App\\Controllers;
	
	use Quellabs\\Canvas\\Annotations\\Route;
	use Quellabs\\Canvas\\Controllers\\BaseController;
	use Symfony\\Component\\HttpFoundation\\Response;
	
	/**
	 * {$controllerName} Controller
	 */
	class {$controllerName}Controller extends BaseController {
	
	    /**
	     * Display the main {$route} view
	     * @Route("/{$route}", methods={"GET"})
	     * @return Response
	     */
	    public function index(): Response {
	        // TODO: Implement your controller logic here
	        return new Response('Hello from {$controllerName}Controller');
	    }
	
	}
PHP;
		}
		
		/**
		 * Ensure the directory structure exists for the given file path
		 * @param string $filePath Complete path to the file that will be created
		 * @return void True if directory exists or was created successfully
		 * @throws \RuntimeException If directory creation fails
		 */
		private function ensureDirectoryExists(string $filePath): void {
			$directory = dirname($filePath);
			
			// Check if directory already exists
			if (is_dir($directory)) {
				return;
			}
			
			// Create directory with recursive flag and appropriate permissions
			if (!mkdir($directory, 0755, true)) {
				throw new \RuntimeException("Failed to create directory: {$directory}");
			}
		}
	}