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

			// Generate configuration content
			$configContents = $this->createConfigFile();

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
		 * Generate rate limiting configuration file content
		 * @return string Complete PHP configuration array content
		 */
		private function createConfigFile(): string {
			return <<<'CONFIG'
<?php

	// Backend used by Quellabs\Canvas\Security\RateLimit\RateLimitStoreFactory to build the
	// RateLimitStoreInterface that RateLimitAspect resolves through dependency injection.
	// Each backend performs the read-decide-write admission cycle as a single atomic
	// operation, so concurrent requests can never read the same count and both be admitted.

	return [
		// Which driver below to use
		'driver'  => 'file',

		'drivers' => [
			// File-backed store: one state file per key, with a single exclusive lock
			// held across the whole read-decide-write cycle. No extra service required;
			// suitable for a single server. Not safe to share across multiple servers
			// unless they share the same filesystem (e.g. NFS) - use redis or memcached
			// for a multi-server deployment.
			'file'      => [
				'class' => \Quellabs\Canvas\Security\RateLimit\FileRateLimitStore::class,

				// Max seconds to wait for a key's lock before failing
				'lock_timeout' => 5,

				// Seconds before an untouched state file is swept as garbage.
				// Must be larger than the longest configured window.
				'stale_after'  => 86400,
			],

			// Redis-backed store: each admission runs as one Lua script (EVAL), atomic
			// on Redis's single-threaded command execution. Recommended for multi-server
			// deployments.
			'redis'     => [
				'class'        => \Quellabs\Canvas\Security\RateLimit\RedisRateLimitStore::class,
				'host'         => '127.0.0.1',
				'port'         => 6379,
				'timeout'      => 2.5,
				'read_timeout' => 2.5,
				'database'     => 0,
				'password'     => null,
			],

			// Memcached-backed store: each admission uses compare-and-swap (CAS) with
			// bounded retries, since Memcached has no server-side scripting.
			'memcached' => [
				'class'   => \Quellabs\Canvas\Security\RateLimit\MemcachedRateLimitStore::class,
				'servers' => [
					['127.0.0.1', 11211, 100],
				],

				// Max CAS retries before a key's admission fails as unavailable
				'max_cas_retries' => 10,
			],
		],
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
