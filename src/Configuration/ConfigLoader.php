<?php
	
	namespace Quellabs\Canvas\Configuration;
	
	use Quellabs\Contracts\Configuration\ConfigProviderInterface;
	use Quellabs\Contracts\Configuration\ConfigurationInterface;
	use Quellabs\Support\ComposerUtils;
	
	class ConfigLoader implements ConfigProviderInterface {
		
		/**
		 * Cache
		 * @var array
		 */
		private array $cache = [];
		
		/**
		 * Load a config file with .local.php override support
		 * @param string $filename Filename to load (with or without .php extension)
		 * @return ConfigurationInterface
		 */
		public function loadConfigFile(string $filename): ConfigurationInterface {
			// Add php extension if it's missing
			if (!str_ends_with($filename, ".php")) {
				$filename .= ".php";
			}
			
			// Fetch from cache if available
			if (isset($this->cache[$filename])) {
				return $this->cache[$filename];
			}
			
			// Resolve config path from project root
			$projectRoot = ComposerUtils::getProjectRoot();
			$configPath = $projectRoot . "/config/{$filename}";
			
			// If the base config file doesn't exist, start with empty array
			if (file_exists($configPath) && is_readable($configPath)) {
				$config = require $configPath;
			} else {
				$config = [];
			}
			
			// Check for .local.php override and merge if present
			$localPath = $projectRoot . "/config/" . pathinfo($filename, PATHINFO_FILENAME) . ".local.php";
			
			if (file_exists($localPath) && is_readable($localPath)) {
				$local = require $localPath;
				$config = array_replace_recursive($config, $local);
			}
			
			// Cache and return
			return $this->cache[$filename] = new Configuration($config);
		}
	}