<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Cron;
	
	use Quellabs\Canvas\TaskScheduler\JobInterface;
	
	/**
	 * Interface for cron-scheduled tasks.
	 * Extends JobInterface with cron-specific metadata: schedule, name, and enabled state.
	 */
	interface TaskInterface extends JobInterface {
		
		/**
		 * Returns the cron expression defining when this task runs (e.g. "0 * * * *")
		 * @return string
		 */
		public function getSchedule(): string;
		
		/**
		 * Returns the unique name identifying this task
		 * @return string
		 */
		public function getName(): string;
		
		/**
		 * Returns a human-readable description of what this task does
		 * @return string
		 */
		public function getDescription(): string;
		
		/**
		 * Returns true if this task is active and should be considered for scheduling
		 * @return bool
		 */
		public function enabled(): bool;
		
		/**
		 * Called when the task exceeds its timeout
		 * @param \Exception $exception
		 * @return void
		 */
		public function onTimeout(\Exception $exception): void;
		
		/**
		 * Called when the task fails for any non-timeout reason
		 * @param \Exception $exception
		 * @return void
		 */
		public function onFailure(\Exception $exception): void;
	}