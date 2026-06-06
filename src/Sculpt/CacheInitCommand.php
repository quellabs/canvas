<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * CacheInitCommand - Create the cache configuration file
	 *
	 * Generates config/cache.php with FileCache as the default driver and
	 * includes commented configuration templates for Redis and Memcached.
	 */
	class CacheInitCommand extends CommandBase {
		
		/**
		 * Returns the signature of this command
		 * @return string The command signature used for CLI invocation
		 */
		public function getSignature(): string {
			return "cache:init";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string Brief description displayed in help output
		 */
		public function getDescription(): string {
			return "Creates the cache configuration file";
		}
		
		/**
		 * Show help information for cache:init
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Creates config/cache.php with FileCache as the default driver. The generated
    file also includes ready-to-use configuration blocks for Redis and Memcached
    that can be activated by changing the default driver key.

USAGE:
    php sculpt cache:init [--force]

OPTIONS:
    --force    Overwrite the existing cache configuration file

EXAMPLES:
    php sculpt cache:init
        Creates config/cache.php; exits with an error if the file already exists

    php sculpt cache:init --force
        Creates or overwrites config/cache.php

NOTES:
    - The config directory is created automatically if it does not exist
    - Default driver is FileCache; Redis and Memcached blocks are included but inactive
HELP;
		}
		
		/**
		 * Execute the cache configuration creation command
		 * @param ConfigurationManager $config Configuration containing command flags and options
		 * @return int Exit code (0 = success, 1 = error)
		 */
		public function execute(ConfigurationManager $config): int {
			// Build complete file path
			$configPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'cache.php';
			
			// Check if file already exists
			if (file_exists($configPath) && !$config->hasFlag('force')) {
				$this->output->writeLn("Cache configuration already exists at: {$configPath}");
				$this->output->writeLn("Use --force to overwrite the existing file.");
				return 1;
			}
			
			// Generate configuration content
			$configContents = $this->createConfigFile();
			
			// Ensure the config directory exists
			$this->ensureDirectoryExists($configPath);
			
			// Write the configuration file
			if (file_put_contents($configPath, $configContents) === false) {
				$this->output->writeLn("Failed to create cache configuration file: {$configPath}");
				return 1;
			}
			
			// Success message
			$this->output->writeLn("Cache configuration created successfully at: {$configPath}");
			
			return 0;
		}
		
		/**
		 * Generate cache configuration file content
		 * @return string Complete PHP configuration array content
		 */
		private function createConfigFile(): string {
			return <<<'CONFIG'
<?php
	
	return [
		'default' => 'file',
		'drivers' => [
			'file'      => [
				'class' => \Quellabs\Canvas\Cache\Drivers\FileCache::class,
			],
			'redis'     => [
				'class'        => \Quellabs\Canvas\Cache\Drivers\RedisCache::class,
				'host'         => '127.0.0.1',
				'port'         => 6379,
				'timeout'      => 2.5,
				'read_timeout' => 2.5,
				'database'     => 0,
				'password'     => null,
			],
			'memcached' => [
				'class'                 => \Quellabs\Canvas\Cache\Drivers\MemcachedCache::class,
				'servers'               => [
					['127.0.0.1', 11211, 100] // [host, port, weight]
				],
				'persistent_id'         => 'cache_pool',
				'compression'           => true,
				'compression_threshold' => 2000, // bytes
			]
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