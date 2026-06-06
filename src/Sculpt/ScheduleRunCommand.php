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
	 * ScheduleRunCommand - Start a task consumer
	 *
	 * Runs a scheduler consumer in the foreground. The cron consumer is built in
	 * and used by default. Additional consumers are discovered via Composer metadata
	 * and selected with the --consumer option.
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
		 * Returns extended help text displayed when --help is passed.
		 * @return string
		 */
		public function getHelp(): string {
			return <<<HELP
DESCRIPTION:
    Starts a scheduler consumer in the foreground. The built-in cron consumer
    is used by default. Additional consumers (e.g. Redis) are resolved by name
    via Composer metadata and must be installed as separate packages.

USAGE:
    php sculpt schedule:run [--consumer=<name>]

OPTIONS:
    --consumer=<name>    Name of the consumer to run (default: cron)

EXAMPLES:
    php sculpt schedule:run
        Starts the built-in cron consumer

    php sculpt schedule:run --consumer=cron
        Explicit equivalent of the default

    php sculpt schedule:run --consumer=redis
        Starts the Redis consumer (requires the Redis consumer package)

NOTES:
    - The command runs in the foreground; use a process manager for production
    - Non-cron consumers are discovered via the "scheduler" Composer metadata key
    - An unknown consumer name exits with code 1 and an explanatory message
HELP;
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