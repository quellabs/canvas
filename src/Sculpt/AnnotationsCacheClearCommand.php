<?php

	namespace Quellabs\Canvas\Sculpt;

	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;

	/**
	 * Clears the whole annotation cache. Outside debug mode a cached file is
	 * trusted as long as it exists, so run this after deploying changed
	 * annotations. Compiled routes have their own cache: routes:clear-cache.
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
			return "Clear annotation cache";
		}

		/**
		 * Returns extended help text, shown by "sculpt help annotations:clear-cache".
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Deletes every cache file the application's annotation reader owns in
    storage/annotations, so annotations are read from source again on the
    next request.

USAGE:
    php sculpt annotations:clear-cache

EXAMPLES:
    php sculpt annotations:clear-cache
        Clears the annotation cache, e.g. after deploying changed entity or
        controller annotations

NOTES:
    - Outside debug mode a cached file is trusted as long as it exists, so
      changed annotations only take effect after clearing the cache
    - Only the active reader's files are removed: docblock caches when
      annotations come from docblocks, attribute caches when they come
      from native attributes
    - Compiled routes have their own cache; clear it with routes:clear-cache
HELP;
		}

		/**
		 * Removes every annotation cache file owned by the application's reader
		 * @param ConfigurationManager $config
		 * @return int
		 */
		public function execute(ConfigurationManager $config): int {
			$this->annotationReader()->clearAllCaches();

			$this->output->success("Annotation cache cleared");

			return 0;
		}

		/**
		 * The application's annotation reader, configured with its cache path
		 * @return AnnotationReader
		 */
		protected function annotationReader(): AnnotationReader {
			return (new Kernel())->getAnnotationsReader();
		}
	}
