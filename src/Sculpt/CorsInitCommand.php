<?php

	namespace Quellabs\Canvas\Sculpt;

	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Support\ComposerUtils;

	/**
	 * CorsInitCommand - Create the CORS configuration file
	 *
	 * Generates config/cors.php with empty allowlists, so the generated file grants
	 * no cross-origin access until the application fills it in. Does not modify
	 * config/app.php; CorsSecurityHeaderPolicy::class must be added to its
	 * security_header_policy list separately to take effect.
	 */
	class CorsInitCommand extends CommandBase {

		/**
		 * Returns the signature of this command
		 * @return string The command signature used for CLI invocation
		 */
		public function getSignature(): string {
			return "cors:init";
		}

		/**
		 * Returns a brief description of what this command is for
		 * @return string Brief description displayed in help output
		 */
		public function getDescription(): string {
			return "Creates the CORS configuration file";
		}

		/**
		 * Show help information for cors:init
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Creates config/cors.php with empty allowlists, 'allow_credentials' set to
    false, and 'max_age' set to 0, so the generated file grants no cross-origin
    access on its own.

USAGE:
    php sculpt cors:init [--force]

OPTIONS:
    --force    Overwrite the existing CORS configuration file

EXAMPLES:
    php sculpt cors:init
        Creates config/cors.php; exits with an error if the file already exists

    php sculpt cors:init --force
        Creates or overwrites config/cors.php

NOTES:
    - The config directory is created automatically if it does not exist
    - Only exact http(s) origins are accepted; '*' and 'null' are not supported
    - After filling in the allowlists, add
      Quellabs\\Canvas\\Security\\Policies\\CorsSecurityHeaderPolicy::class to
      config/app.php's security_header_policy; this command never edits
      config/app.php itself
HELP;
		}

		/**
		 * Execute the CORS configuration creation command
		 * @param ConfigurationManager $config Configuration containing command flags and options
		 * @return int Exit code (0 = success, 1 = error)
		 */
		public function execute(ConfigurationManager $config): int {
			// Build complete file path
			$configPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'cors.php';

			// Check if file already exists
			if (file_exists($configPath) && !$config->hasFlag('force')) {
				$this->output->writeLn("CORS configuration already exists at: {$configPath}");
				$this->output->writeLn("Use --force to overwrite the existing file.");
				return 1;
			}

			// Generate configuration content
			$configContents = $this->createConfigFile();

			// Ensure the config directory exists
			try {
				$this->ensureDirectoryExists($configPath);
			} catch (\RuntimeException $e) {
				$this->output->writeLn($e->getMessage());
				return 1;
			}

			// Write the configuration file
			if (file_put_contents($configPath, $configContents) === false) {
				$this->output->writeLn("Failed to create CORS configuration file: {$configPath}");
				return 1;
			}

			$this->output->writeLn("CORS configuration created successfully at: {$configPath}");
			$this->output->writeLn("Next steps:");
			$this->output->writeLn("  1. Fill in allowed_origins, allowed_methods, allowed_headers, and exposed_headers");
			$this->output->writeLn("  2. Add Quellabs\\Canvas\\Security\\Policies\\CorsSecurityHeaderPolicy::class to config/app.php's security_header_policy");

			return 0;
		}

		/**
		 * Generate CORS configuration file content
		 * @return string Complete PHP configuration array content
		 */
		private function createConfigFile(): string {
			return <<<'CONFIG'
<?php

	// Read by Quellabs\Canvas\Security\Policies\CorsSecurityHeaderPolicy, which must be
	// added to config/app.php's security_header_policy (this file alone does nothing).
	// Absent entries default to empty/false/0, so an unfilled file grants no cross-origin
	// access. Only exact http(s) origins are accepted — wildcard '*' and the opaque 'null'
	// origin are not supported.

	return [
		// Exact scheme+host(+port) origins allowed cross-origin access, e.g.
		// 'https://app.example.com' or 'https://admin.example.com:8443'.
		'allowed_origins'   => [],

		// HTTP methods allowed cross-origin, e.g. ['GET', 'POST', 'PATCH', 'DELETE'].
		'allowed_methods'   => [],

		// Request headers a cross-origin script may send, e.g. ['Content-Type', 'Authorization'].
		'allowed_headers'   => [],

		// Response headers exposed to cross-origin scripts via Access-Control-Expose-Headers.
		'exposed_headers'   => [],

		// Whether to send Access-Control-Allow-Credentials: true for allowed origins.
		'allow_credentials' => false,

		// Access-Control-Max-Age in seconds (how long a browser may cache a preflight
		// result). 0 omits the header.
		'max_age'           => 0,
	];
CONFIG;
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
