<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Cron;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\Support\ComposerUtils;
	use Quellabs\Contracts\TaskScheduler\ConsumerInterface;
	use Quellabs\Canvas\TaskScheduler\Storage\FileJobStorage;
	
	/**
	 * Cron-based task scheduler consumer.
	 * Discovered via the "task-scheduler" Composer family and selected
	 * by Sculpt when --consumer=cron is specified (or by default).
	 */
	class CronConsumer implements ConsumerInterface {
		
		/**
		 * @var array<string, mixed>
		 */
		private array $config = [];
		
		/**
		 * Returns the identifier used to select this consumer via CLI
		 * @return string
		 */
		public static function getName(): string {
			return 'cron';
		}
		
		/**
		 * Returns metadata about this consumer for discovery
		 * @return array<string, mixed>
		 */
		public static function getMetadata(): array {
			return [
				'name'        => self::getName(),
				'description' => 'Cron-based task scheduler',
			];
		}
		
		/**
		 * Returns the configuration
		 * @return array<string, mixed>
		 */
		public function getConfig(): array {
			return $this->config;
		}
		
		/**
		 * Sets configuration
		 * @param array<string, mixed> $config
		 * @return void
		 */
		public function setConfig(array $config): void {
			$this->config = $config;
		}
		
		/**
		 * Start the cron consumer and run all due tasks.
		 * Loads its own configuration via the Kernel.
		 * @return void
		 */
		public function run(): void {
			$kernel = new Kernel();
			$container = $kernel->getDependencyInjector();
			$tasksPath = $kernel->getConfiguration()->get('task_scheduler_directory', ComposerUtils::getProjectRoot() . '/src/Tasks');
			$fileJobStorage = new FileJobStorage(ComposerUtils::getProjectRoot() . '/storage/task-scheduler');
			
			$scheduler = new TaskScheduler($fileJobStorage, $container, $tasksPath);
			$scheduler->run();
		}
	}