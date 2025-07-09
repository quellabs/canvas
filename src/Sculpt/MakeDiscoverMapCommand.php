<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\AnnotationResolver;
	use Quellabs\Discover\Composer\ServiceDiscoveryPlugin;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Symfony\Component\HttpFoundation\Request;
	
	class MakeDiscoverMapCommand extends CommandBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "make:discovery-mapping";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "Creates a discovery map file";
		}
		
		/**
		 * List the routes
		 * @param ConfigurationManager $config
		 * @return int
		 */
		public function execute(ConfigurationManager $config): int {
			$discoverComposer = new ServiceDiscoveryPlugin();
			$discoverComposer->onPostUpdate();
		}
	}