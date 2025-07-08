<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Runner;
	
	use Psr\Log\LoggerInterface;
	use Quellabs\Contracts\TaskScheduler\TaskInterface;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	
	/**
	 * A timeout strategy implementation that does not enforce any timeout limits.
	 * This strategy simply executes tasks without any time restrictions or interruptions.
	 *
	 * This is useful for tasks that:
	 * - Need to run to completion regardless of execution time
	 * - Have unpredictable execution times
	 * - Are critical and should not be interrupted
	 *
	 * @package Quellabs\Canvas\TaskScheduler\Runner
	 */
	class StrategyNoTimeout implements TaskRunnerInterface {
		
		/**
		 * Logger instance for recording timeout events and errors
		 * @var LoggerInterface
		 */
		private LoggerInterface $logger;
		
		/**
		 * @var int Maximum execution time in seconds (ignored by this strategy)
		 */
		private int $timeout;
		
		/**
		 * Constructor - Initialize the strategy with a logger
		 * @param int $timeout Maximum execution time in seconds (ignored by this strategy)
		 * @param LoggerInterface $logger Logger for recording timeout events and task execution info
		 */
		public function __construct(int $timeout, LoggerInterface $logger) {
			$this->timeout = $timeout;
			$this->logger = $logger;
		}
		
		/**
		 * Executes a task without any timeout restrictions
		 * @param TaskInterface $task The task to execute
		 * @throws \Exception Any exception thrown by the task's handle() method
		 */
		public function run(TaskInterface $task): void {
			try {
				// Execute the task without any timeout enforcement
				// The task will run until completion, or until it throws an exception
				$task->handle();
				
				// Log successful completion
				$this->logger->info('Task completed successfully', [
					'task_class' => get_class($task)
				]);
			} catch (\Exception $e) {
				// Log any exceptions that occur during task execution
				$this->logger->error('Task execution failed', [
					'task_class'      => get_class($task),
					'error'           => $e->getMessage(),
					'exception_class' => get_class($e)
				]);
				
				// Re-throw the exception to maintain the original error handling flow
				throw $e;
			}
		}
	}