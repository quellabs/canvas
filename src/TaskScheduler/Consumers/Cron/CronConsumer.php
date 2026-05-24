<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Cron;
	
	use Quellabs\Contracts\TaskScheduler\ConsumerInterface;
	
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
			$scheduler = new TaskScheduler();
			$scheduler->run();
		}
	}