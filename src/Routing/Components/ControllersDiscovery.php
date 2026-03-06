<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Scanner\MetadataCollector;
	use Quellabs\Support\ComposerUtils;
	
	class ControllersDiscovery {
		private Kernel $kernel;
		
		/**
		 * Constructor
		 * @param Kernel $kernel
		 */
		public function __construct(Kernel $kernel) {
			$this->kernel = $kernel;
		}
		
		/**
		 * Gets the absolute paths to all controller directories
		 * @return array Absolute paths to controller directories
		 */
		public function fetch(): array {
			// Get contents of config/app.php
			$configuration = $this->kernel->getConfiguration();
			
			// Build the default controller path relative to the project root
			$defaultRouterPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "Controllers";
			
			// Allow the controller directory to be overridden via configuration
			$routerPath = $configuration->get('controller_directory', $defaultRouterPath);
			
			// Only include the configured path if it actually exists on disk
			$result = [];
			
			if (is_dir($routerPath)) {
				$result[] = $routerPath;
			}
			
			// Discover additional controller directories registered by installed packages
			$discover = new Discover();
			$discover->addScanner(new MetadataCollector("canvas"));
			$discover->discover();
			
			// Merge local controller path with any paths advertised by packages,
			// filtering out any that don't exist on disk
			$packagePaths = array_filter(
				$discover->getFamilyValues('canvas', 'controller'),
				fn($path) => is_dir($path)
			);
			
			// Return result
			return array_merge($result, $packagePaths);
		}
	}