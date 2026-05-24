<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Cron;
	
	use Quellabs\Canvas\TaskScheduler\Storage\FileJobStorage;
	use Quellabs\Contracts\TaskScheduler\ConsumerInterface;
	use Quellabs\Support\ComposerUtils;
	
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
		 * Loads its own configuration from app.php.
		 * @return void
		 */
		public function run(): void {
			$projectRoot = ComposerUtils::getProjectRoot();
			
			if (file_exists($projectRoot . '/config/app.php')) {
				$appConfig = require $projectRoot . '/config/app.php';
			} else {
				$appConfig = [];
			}
			
			$tasksPath = $appConfig['task_scheduler_directory'] ?? $projectRoot . '/src/Tasks';
			
			$scheduler = new TaskScheduler(
				new FileJobStorage($projectRoot . '/storage/task-scheduler'),
				$tasksPath
			);
			
			$scheduler->run();
		}
	}