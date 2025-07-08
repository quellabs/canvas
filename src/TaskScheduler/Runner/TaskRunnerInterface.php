<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Runner;
	
	use Quellabs\Contracts\TaskScheduler\TaskException;
	use Quellabs\Contracts\TaskScheduler\TaskInterface;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	
	/**
	 * Interface for timeout strategy implementations.
	 */
	interface TaskRunnerInterface {
		
		/**
		 * Executes a task with a specified timeout limit.
		 * @param TaskInterface $task The task to execute
		 * @throws TaskTimeoutException If the task exceeds the specified timeout
		 * @throws TaskException If the task fails to execute or encounters an error
		 * @return void
		 */
		public function run(TaskInterface $task): void;
	}