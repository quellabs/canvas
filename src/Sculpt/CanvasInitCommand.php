<?php

	namespace Quellabs\Canvas\Sculpt;

	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Support\ComposerUtils;

	/**
	 * CanvasInitCommand - Create the Canvas application configuration file
	 *
	 * Generates config/app.php with sensible defaults for the directory layout,
	 * template engine, output filter, annotation source, and the basic security
	 * header policy.
	 */
	class CanvasInitCommand extends CommandBase {

		/**
		 * Returns the signature of this command
		 * @return string The command signature used for CLI invocation
		 */
		public function getSignature(): string {
			return "canvas:init";
		}

		/**
		 * Returns a brief description of what this command is for
		 * @return string Brief description displayed in help output
		 */
		public function getDescription(): string {
			return "Creates the Canvas application configuration file";
		}

		/**
		 * Show help information for canvas:init
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Creates config/app.php with sensible defaults: debug mode on, the 'smarty'
    template engine, HtmlMinifyFilter as the output filter, the standard
    src/Controllers, src/Errors, src/Aspects, src/Entities, and src/Listeners
    directories, attribute-based annotations, and BasicSecurityHeaderPolicy
    as the default security header policy.

USAGE:
    php sculpt canvas:init [--force]

OPTIONS:
    --force    Overwrite the existing Canvas configuration file

EXAMPLES:
    php sculpt canvas:init
        Creates config/app.php; exits with an error if the file already exists

    php sculpt canvas:init --force
        Creates or overwrites config/app.php

NOTES:
    - The config directory is created automatically if it does not exist
    - Turn off 'debug_mode' in production
    - Set 'security_header_policy' to null to disable the default security headers
HELP;
		}

		/**
		 * Execute the Canvas configuration creation command
		 * @param ConfigurationManager $config Configuration containing command flags and options
		 * @return int Exit code (0 = success, 1 = error)
		 */
		public function execute(ConfigurationManager $config): int {
			// Build complete file path
			$configPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'app.php';

			// Check if file already exists
			if (file_exists($configPath) && !$config->hasFlag('force')) {
				$this->output->writeLn("Canvas configuration already exists at: {$configPath}");
				$this->output->writeLn("Use --force to overwrite the existing file.");
				return 1;
			}

			// Load configuration content from the shipped stub
			$configContents = $this->loadStub();

			if ($configContents === false) {
				$this->output->writeLn("Failed to read Canvas configuration stub at: {$this->getStubPath()}");
				return 1;
			}

			// Ensure the config directory exists
			try {
				$this->ensureDirectoryExists($configPath);
			} catch (\RuntimeException $e) {
				$this->output->writeLn($e->getMessage());
				return 1;
			}

			// Write the configuration file
			if (file_put_contents($configPath, $configContents) === false) {
				$this->output->writeLn("Failed to create Canvas configuration file: {$configPath}");
				return 1;
			}

			$this->output->writeLn("Canvas configuration created successfully at: {$configPath}");

			return 0;
		}

		/**
		 * Returns the path to the shipped configuration stub
		 * @return string Absolute path to the stub file
		 */
		private function getStubPath(): string {
			return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'app.php';
		}

		/**
		 * Read the shipped configuration stub
		 * @return string|false Stub file contents, or false on failure
		 */
		private function loadStub(): string|false {
			return file_get_contents($this->getStubPath());
		}

		/**
		 * Ensure the directory structure exists for the given file path
		 * @param string $filePath Complete path to the file that will be created
		 * @return void
		 * @throws \RuntimeException If directory creation fails
		 */
		private function ensureDirectoryExists(string $filePath): void {
			$directory = dirname($filePath);

			// Check if directory already exists
			if (is_dir($directory)) {
				return;
			}

			// A non-directory file already occupies this path: fail with a precise
			// message instead of letting mkdir() emit its own E_WARNING for it.
			if (file_exists($directory)) {
				throw new \RuntimeException("Cannot create directory, a file already exists at: {$directory}");
			}

			// Create directory with recursive flag and appropriate permissions
			if (!mkdir($directory, 0755, true)) {
				throw new \RuntimeException("Failed to create directory: {$directory}");
			}
		}
	}
