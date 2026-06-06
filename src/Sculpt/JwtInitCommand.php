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
			
			// Generate configuration content
			$configContents = $this->createConfigFile();
			
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
		 * Generate JWT configuration file content
		 * @return string Complete PHP configuration array content
		 */
		private function createConfigFile(): string {
			return <<<'CONFIG'
<?php
	
	return [
		// HMAC secret used to verify token signatures.
		// Leave empty here — set the real value in config/jwt.local.php,
		// which should not be committed to source control.
		'secret'           => '',
		
		// Signing algorithm. Only HS256 is currently supported.
		'algorithm'        => 'HS256',
		
		// When true, authentication failures throw JwtAuthenticationException.
		// When false (default), failures set 'jwt_error' on request attributes
		// and the controller decides how to respond.
		// Requires a registered ErrorHandlerInterface to produce a proper JSON
		// response in exception mode; the default Canvas handler returns HTML.
		'throw_on_failure' => false,
		
		// Seconds of clock skew tolerance applied to exp and nbf claim validation.
		// Compensates for minor time differences between token issuer and this server.
		// Must be >= 0.
		'clock_skew'       => 30,
		
		// Expected value of the 'iss' (issuer) claim.
		// Leave empty to skip issuer validation.
		'issuer'           => '',
		
		// Expected value of the 'aud' (audience) claim.
		// Leave empty to skip audience validation.
		'audience'         => '',
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
			
			// Create directory with recursive flag and appropriate permissions
			if (!mkdir($directory, 0755, true)) {
				throw new \RuntimeException("Failed to create directory: {$directory}");
			}
		}
	}