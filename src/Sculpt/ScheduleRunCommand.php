<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Sculpt\Contracts\CommandBase;
	use Quellabs\Canvas\Scheduler\Cron\CronConsumer;
	use Quellabs\Contracts\Scheduler\ConsumerInterface;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Scanner\ComposerScanner;
	
	/**
	 * Unified queue/scheduler work command.
	 * Cron is the default consumer and is instantiated directly.
	 * Other consumers are discovered via Composer metadata.
	 *
	 * Usage:
	 *   php sculpt schedule:run                    — runs cron consumer (default)
	 *   php sculpt schedule:run --consumer=redis   — runs Redis consumer
	 *   php sculpt schedule:run --consumer=cron    — explicit cron
	 */
	class ScheduleRunCommand extends CommandBase {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "schedule:run";
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
			$kernel = new Kernel();
			$consumerName = $config->getAsString('consumer', 'cron');
			
			// Cron is the built-in default — instantiate directly without discovery
			if ($consumerName === 'cron') {
				$consumer = new CronConsumer($kernel);
				$consumer->run();
				return 0;
			}
			
			// All other consumers are discovered via Composer metadata
			$discover = new Discover();
			$discover->addScanner(new ComposerScanner("scheduler"));
			$discover->discover();
			
			foreach ($discover->getDefinitions() as $definition) {
				if (!is_a($definition->className, ConsumerInterface::class, true)) {
					continue;
				}
				
				if ($definition->className::getName() !== $consumerName) {
					continue;
				}
				
				/** @var ConsumerInterface $consumer */
				$consumer = $kernel->getDependencyInjector()->make($definition->className);
				$consumer->run();
				return 0;
			}
			
			$this->output->writeln("Unknown consumer '{$consumerName}'. Is the package installed?");
			return 1;
		}
	}