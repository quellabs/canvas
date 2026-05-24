<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Contracts\TaskScheduler\ConsumerInterface;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Scanner\ComposerScanner;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * Unified queue/scheduler work command.
	 * Discovers all registered consumers and delegates to the one matching
	 * --consumer (defaults to "cron" if not specified).
	 *
	 * Usage:
	 *   php sculpt queue:work                    — runs cron consumer (default)
	 *   php sculpt queue:work --consumer=redis   — runs Redis consumer
	 *   php sculpt queue:work --consumer=cron    — explicit cron
	 */
	class QueueWorkCommand extends RoutesBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "queue:work";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "Start a task consumer (default: cron)";
		}
		
		/**
		 * Execute the command
		 * @param ConfigurationManager $config
		 * @return int Exit code
		 */
		public function execute(ConfigurationManager $config): int {
			// Fetch the consumer we want to use. Default to 'cron'.
			$consumerName = $config->getAsString('consumer', 'cron');
			
			// Discover all registered consumers via Composer metadata
			$discover = new Discover();
			$discover->addScanner(new ComposerScanner('task-scheduler'));
			$discover->discover();
			
			// Find the consumer matching the requested name
			foreach ($discover->getProviders() as $provider) {
				if (!$provider instanceof ConsumerInterface) {
					continue;
				}
				
				if ($provider::getName() !== $consumerName) {
					continue;
				}
				
				$provider->run();
				return 0;
			}
			
			$this->output->writeln("Unknown consumer '{$consumerName}'. Is the package installed?");
			return 1;
		}
	}