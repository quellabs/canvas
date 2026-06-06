<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Support\ComposerUtils;
	use Quellabs\Canvas\Annotations\Route;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	
	class RoutesCacheClearCommand extends CommandBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "routes:clear-cache";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "Clear routing cache";
		}
		
		/**
		 * List the routes
		 * @param ConfigurationManager $config
		 * @return int
		 */
		public function execute(ConfigurationManager $config): int {
			// Remove annotation cache files
			$kernel = new Kernel();
			$kernel->getAnnotationsReader()->clearCacheByAnnotationClass(Route::class);
			
			// Remove compiled routes
			$files = glob(ComposerUtils::getProjectRoot() . '/storage/cache/routes/*');
			
			if ($files !== false) {
				foreach ($files as $file) {
					if (is_file($file)) {
						@unlink($file);
					}
				}
			}
			
			// Show message
			$this->output->success("Routes cache cleared");
			
			// Return success status
			return 0;
		}
	}