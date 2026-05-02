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
		 * Gets controller directories and class names from packages
		 * @return array<string> Absolute paths to controller directories and/or fully qualified class names
		 */
		public function fetch(): array {
			// Get contents of config/app.php
			$configuration = $this->kernel->getConfiguration();
			
			// Build the default controller path relative to the project root
			$defaultRouterPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "Controllers";
			
			// Allow the controller directory to be overridden via configuration
			$routerPath = $configuration->get('controller_directory', $defaultRouterPath);
			
			// Scan the local controller directory for classes
			$result = is_dir($routerPath)
				? ComposerUtils::findClassesInDirectory($routerPath)
				: [];
			
			// Discover controller class names registered by installed packages
			$discover = new Discover();
			$discover->addScanner(new MetadataCollector("canvas"));
			$discover->discover();
			
			// Collect class names advertised by packages
			$packageClasses = array_filter(
				$discover->getFamilyValues('canvas', 'controller'),
				fn($value) => is_string($value) && class_exists($value)
			);
			
			// Return a flat list of fully qualified controller class names
			return array_merge($result, array_values($packageClasses));
		}
	}