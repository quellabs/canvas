<?php

	namespace Quellabs\Canvas\Sculpt;

	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Support\ComposerUtils;

	/**
	 * RateLimitInitCommand - Create the rate limiting configuration file
	 *
	 * Generates config/rate_limit.php with the file-backed store as the default
	 * driver and includes ready-to-use configuration blocks for Redis and Memcached.
	 */
	class RateLimitInitCommand extends CommandBase {

		/**
		 * Returns the signature of this command
		 * @return string The command signature used for CLI invocation
		 */
		public function getSignature(): string {
			return "rate-limit:init";
		}

		/**
		 * Returns a brief description of what this command is for
		 * @return string Brief description displayed in help output
		 */
		public function getDescription(): string {
			return "Creates the rate limiting configuration file";
		}

		/**
		 * Show help information for rate-limit:init
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Creates config/rate_limit.php with the file-backed store as the default
    driver. The generated file also includes ready-to-use configuration blocks
    for Redis and Memcached that can be activated by changing the default
    driver key.

USAGE:
    php sculpt rate-limit:init [--force]

OPTIONS:
    --force    Overwrite the existing rate limiting configuration file

EXAMPLES:
    php sculpt rate-limit:init
        Creates config/rate_limit.php; exits with an error if the file already exists

    php sculpt rate-limit:init --force
        Creates or overwrites config/rate_limit.php

NOTES:
    - The config directory is created automatically if it does not exist
    - Default driver is the file-backed store; Redis and Memcached blocks are
      included but inactive
    - The file-backed store is not safe to share across multiple servers unless
      they share the same filesystem; use redis or memcached for a multi-server
      deployment
HELP;
		}

		/**
		 * Execute the rate limiting configuration creation command
		 * @param ConfigurationManager $config Configuration containing command flags and options
		 * @return int Exit code (0 = success, 1 = error)
		 */
		public function execute(ConfigurationManager $config): int {
			// Build complete file path
			$configPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'rate_limit.php';

			// Check if file already exists
			if (file_exists($configPath) && !$config->hasFlag('force')) {
				$this->output->writeLn("Rate limiting configuration already exists at: {$configPath}");
				$this->output->writeLn("Use --force to overwrite the existing file.");
				return 1;
			}

			// Load configuration content from the shipped stub
			$configContents = $this->loadStub();

			if ($configContents === false) {
				$this->output->writeLn("Failed to read rate limiting configuration stub at: {$this->getStubPath()}");
				return 1;
			}

			// Ensure the config directory exists
			$this->ensureDirectoryExists($configPath);

			// Write the configuration file
			if (file_put_contents($configPath, $configContents) === false) {
				$this->output->writeLn("Failed to create rate limiting configuration file: {$configPath}");
				return 1;
			}

			// Success message
			$this->output->writeLn("Rate limiting configuration created successfully at: {$configPath}");

			return 0;
		}

		/**
		 * Returns the path to the shipped configuration stub
		 * @return string Absolute path to the stub file
		 */
		private function getStubPath(): string {
			return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'rate_limit.php';
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
