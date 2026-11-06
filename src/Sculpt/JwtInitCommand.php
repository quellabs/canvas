<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * JwtInitCommand - Create the JWT configuration file
	 *
	 * Generates config/jwt.php with HS256 as the default algorithm and sensible
	 * defaults for clock skew and failure mode. The secret is intentionally left
	 * empty and must be set in config/jwt.local.php, which should not be committed
	 * to source control.
	 */
	class JwtInitCommand extends CommandBase {
		
		/**
		 * Returns the signature of this command
		 * @return string The command signature used for CLI invocation
		 */
		public function getSignature(): string {
			return "jwt:init";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string Brief description displayed in help output
		 */
		public function getDescription(): string {
			return "Creates the JWT configuration file";
		}
		
		/**
		 * Show help information for jwt:init
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Creates config/jwt.php with HS256 as the default signing algorithm and
    sensible defaults for clock skew tolerance and failure mode. The secret
    key is intentionally left empty and must be set separately in
    config/jwt.local.php, which should not be committed to source control.

USAGE:
    php sculpt jwt:init [--force]

OPTIONS:
    --force    Overwrite the existing JWT configuration file

EXAMPLES:
    php sculpt jwt:init
        Creates config/jwt.php; exits with an error if the file already exists

    php sculpt jwt:init --force
        Creates or overwrites config/jwt.php

NOTES:
    - After running, add config/jwt.local.php to your .gitignore
    - Create config/jwt.local.php and set 'secret' to a strong random value
    - Default failure mode is attribute mode (throw_on_failure = false); failures
      set 'jwt_error' on request attributes instead of throwing an exception
    - Clock skew tolerance defaults to 30 seconds
HELP;
		}
		
		/**
		 * Execute the JWT configuration creation command
		 * @param ConfigurationManager $config Configuration containing command flags and options
		 * @return int Exit code (0 = success, 1 = error)
		 */
		public function execute(ConfigurationManager $config): int {
			// Build complete file path
			$configPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'jwt.php';
			
			// Check if file already exists
			if (file_exists($configPath) && !$config->hasFlag('force')) {
				$this->output->writeLn("JWT configuration already exists at: {$configPath}");
				$this->output->writeLn("Use --force to overwrite the existing file.");
				return 1;
			}
			
			// Load configuration content from the shipped stub
			$configContents = $this->loadStub();

			if ($configContents === false) {
				$this->output->writeLn("Failed to read JWT configuration stub at: {$this->getStubPath()}");
				return 1;
			}

			// Ensure the config directory exists
			$this->ensureDirectoryExists($configPath);
			
			// Write the configuration file
			if (file_put_contents($configPath, $configContents) === false) {
				$this->output->writeLn("Failed to create JWT configuration file: {$configPath}");
				return 1;
			}
			
			$this->output->writeLn("JWT configuration created successfully at: {$configPath}");
			$this->output->writeLn("Next steps:");
			$this->output->writeLn("  1. Add config/jwt.local.php to your .gitignore");
			$this->output->writeLn("  2. Create config/jwt.local.php and set 'secret' to a strong random value");
			
			return 0;
		}
		
		/**
		 * Returns the path to the shipped configuration stub
		 * @return string Absolute path to the stub file
		 */
		private function getStubPath(): string {
			return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'jwt.php';
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
			
			// Create directory with recursive flag and appropriate permissions
			if (!mkdir($directory, 0755, true)) {
				throw new \RuntimeException("Failed to create directory: {$directory}");
			}
		}
	}