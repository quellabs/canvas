<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Cron;
	
	/**
	 * Abstract base class for cron tasks.
	 * Provides default implementations of ProviderInterface boilerplate
	 * so task authors only need to implement the task-specific methods.
	 */
	abstract class AbstractTask implements TaskInterface {
		
		/**
		 * @var array<string, mixed>
		 */
		private array $config = [];
		
		/**
		 * Returns metadata about this task for discovery.
		 * Override to provide custom metadata.
		 * @return array<string, mixed>
		 */
		public static function getMetadata(): array {
			return [];
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
		 * No retries by default for cron tasks
		 * @return int
		 */
		public function getMaxRetries(): int {
			return 0;
		}
		
		/**
		 * No timeout by default
		 * @return int
		 */
		public function getTimeout(): int {
			return 0;
		}
		
		/**
		 * Default timeout handler — override to add custom behaviour
		 * @param \Exception $exception
		 * @return void
		 */
		public function onTimeout(\Exception $exception): void {
		}
		
		/**
		 * Default failure handler — override to add custom behaviour
		 * @param \Exception $exception
		 * @return void
		 */
		public function onFailure(\Exception $exception): void {
		}
	}