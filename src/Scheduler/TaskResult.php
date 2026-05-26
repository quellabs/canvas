<?php
	
	namespace Quellabs\Canvas\Scheduler;
	
	use Quellabs\Canvas\Scheduler\Cron\TaskInterface;
	
	/**
	 * Execution result for a cron task.
	 * Extends JobResult with the task name accessor specific to cron tasks.
	 */
	readonly class TaskResult extends JobResult {
		
		/**
		 * Returns the name of the task that produced this result
		 * @return string
		 */
		public function getTaskName(): string {
			/** @var TaskInterface $task */
			$task = $this->job;
			return $task->getName();
		}
	}
