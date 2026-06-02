<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Annotations\Route;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Support\ComposerUtils;
	use Quellabs\AnnotationReader\AnnotationReader;
	
	class RoutesCacheClearCommand extends RoutesBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "route:clear-cache";
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
			// Remove the cache files
			$kernel = new Kernel();
			$kernel->getAnnotationsReader()->clearCacheByAnnotationClass(Route::class);
			
			// Show message
			$this->output->success("Routes cache cleared");
			
			// Return success status
			return 0;
		}
	}