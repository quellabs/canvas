<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	
	/**
	 * AnnotationsCacheClearCommand - Clear all annotation caches
	 *
	 * Removes all annotation cache and manifest files so that the next request
	 * rebuilds the annotation metadata from scratch.
	 */
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
		 * Returns extended help text displayed when --help is passed.
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Removes all annotation cache and manifest files across the entire application.
    Run this after modifying any annotation class or annotated class to ensure
    stale cached metadata is not used.

USAGE:
    php sculpt annotations:clear-cache

EXAMPLES:
    php sculpt annotations:clear-cache
        Clears all annotation caches; they are rebuilt automatically on next use

NOTES:
    - Clears all annotation types, unlike route:clear-cache or quel:clear-cache
      which are scoped to specific annotation classes
    - Safe to run in production; caches are rebuilt automatically on next access
HELP;
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