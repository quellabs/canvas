<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Runner;
	
	use Psr\Log\LoggerInterface;
	use Quellabs\Canvas\TaskScheduler\JobInterface;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	
	/**
	 * A runner strategy that does not enforce any timeout limits.
	 * This strategy simply executes jobs without any time restrictions or interruptions.
	 *
	 * This is useful for jobs that:
	 * - Need to run to completion regardless of execution time
	 * - Have unpredictable execution times
	 * - Are critical and should not be interrupted
	 */
	class StrategyNoTimeout implements TaskRunnerInterface {
		
		/**
		 * Logger instance for recording execution events and errors
		 * @var LoggerInterface
		 */
		private LoggerInterface $logger;
		
		/**
		 * Constructor - Initialize the strategy with a logger
		 * @param LoggerInterface $logger Logger for recording execution events
		 */
		public function __construct(LoggerInterface $logger) {
			$this->logger = $logger;
		}
		
		/**
		 * Executes a job without any timeout restrictions
		 * @param JobInterface $job The job to execute
		 * @throws \Exception Any exception thrown by the job's handle() method
		 */
		public function run(JobInterface $job): void {
			try {
				// Execute the job without any timeout enforcement
				// The job will run until completion, or until it throws an exception
				$job->handle();
				
				// Log successful completion
				$this->logger->info('Job completed successfully', [
					'job_class' => get_class($job)
				]);
			} catch (\Exception $e) {
				// Log any exceptions that occur during job execution
				$this->logger->error('Job execution failed', [
					'job_class'       => get_class($job),
					'error'           => $e->getMessage(),
					'exception_class' => get_class($e)
				]);
				
				// Re-throw the exception to maintain the original error handling flow
				throw $e;
			}
		}
	}
