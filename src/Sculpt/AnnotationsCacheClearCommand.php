<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	
	class AnnotationsCacheClearCommand extends CommandBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "annotations:clear-cache";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "Clear all annotation caches";
		}
		
		/**
		 * Clear all annotation cache files
		 * @param ConfigurationManager $config
		 * @return int
		 */
		public function execute(ConfigurationManager $config): int {
			// Remove all annotation cache and manifest files
			$kernel = new Kernel();
			$kernel->getAnnotationsReader()->clearAllCaches();
			
			// Show message
			$this->output->success("Annotation cache cleared");
			
			// Return success status
			return 0;
		}
	}