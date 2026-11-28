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
