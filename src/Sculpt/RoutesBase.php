<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Routing\AnnotationLister;
	use Quellabs\Contracts\Discovery\ProviderInterface;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Sculpt\Console\ConsoleInput;
	use Quellabs\Sculpt\Console\ConsoleOutput;
	use Quellabs\Sculpt\Contracts\CommandBase;
	
	abstract class RoutesBase extends CommandBase {
		
		/**
		 * Class used for listing annotations
		 * @var AnnotationLister
		 */
		protected AnnotationLister $lister;
		
		/**
		 * RoutesBase constructor
		 * @param ConsoleInput $input
		 * @param ConsoleOutput $output
		 * @param ProviderInterface|null $provider
		 */
		public function __construct(ConsoleInput $input, ConsoleOutput $output, ?ProviderInterface $provider = null) {
			parent::__construct($input, $output, $provider);

			// Config for AnnotationsReader
			// Instantiate annotation listing class
			$this->lister = new AnnotationLister();
		}

		/**
		 * Discovers and builds a complete list of all routes in the application
		 * by scanning controller classes and their annotated methods
		 * @return array Array of route configurations with controller, method, route, and aspects info
		 */
		protected function getRoutes(ConfigurationManager $config): array {
			return $this->lister->getRoutes($config);
		}
	}