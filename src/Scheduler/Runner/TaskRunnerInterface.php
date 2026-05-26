<?php
	
	namespace Quellabs\Canvas\Scheduler\Runner;
	
	use Quellabs\Contracts\Scheduler\JobInterface;
	use Quellabs\Contracts\Scheduler\TaskException;
	use Quellabs\Contracts\Scheduler\TaskTimeoutException;
	
	/**
	 * Interface for job runner strategy implementations.
	 * Runners are responsible for executing a job with optional timeout enforcement.
	 */
	interface TaskRunnerInterface {
		
		/**
		 * Execute a job, optionally enforcing a timeout
		 * @param JobInterface $job The job to execute
		 * @return void
		 * @throws TaskException If the job fails to execute or encounters an error
		 * @throws TaskTimeoutException If the job exceeds the specified timeout
		 */
		public function run(JobInterface $job): void;
	}
