<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Runner;
	
	use Psr\Log\LoggerInterface;
	use Quellabs\Contracts\TaskScheduler\TaskFailException;
	use Quellabs\Contracts\TaskScheduler\TaskInterface;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	
	/**
	 * Timeout strategy implementation using PCNTL (Process Control) functions
	 * to enforce execution time limits on tasks. This strategy uses SIGALRM
	 * signals to interrupt task execution when the specified timeout period is exceeded.
	 */
	class StrategyPcntl implements TaskRunnerInterface {
		
		/**
		 * @var int Maximum execution time in seconds
		 */
		private int $timeout;
		
		/**
		 * Logger instance for recording timeout events and errors
		 * @var LoggerInterface
		 */
		private LoggerInterface $logger;
		
		/**
		 * Constructor - initializes the strategy with a logger instance.
		 * @param int $timeout Maximum execution time in seconds
		 * @param LoggerInterface $logger Logger for debugging and error reporting
		 */
		public function __construct(int $timeout, LoggerInterface $logger) {
			$this->timeout = $timeout;
			$this->logger = $logger;
		}
		
		/**
		 * Executes a task with a specified timeout using PCNTL alarm signals
		 * @param TaskInterface $task The task to execute
		 * @throws \RuntimeException If PCNTL functions are not available
		 * @throws TaskTimeoutException If the task execution exceeds the timeout
		 * @throws \Exception
		 */
		public function run(TaskInterface $task): void {
			// Check if required PCNTL functions are available on this system
			if (!function_exists('pcntl_fork') || !function_exists('pcntl_alarm')) {
				throw new \RuntimeException('PCNTL functions not available');
			}
			
			// Set up signal handler for SIGALRM to throw timeout exception
			pcntl_signal(SIGALRM, function () use ($task) {
				throw new TaskTimeoutException("Task {$task->getName()} timed out");
			});
			
			// Set the alarm to trigger after the specified timeout duration
			pcntl_alarm($this->timeout);
			
			try {
				// Execute the task - this will be interrupted by SIGALRM if timeout is exceeded
				$task->handle();
				
			} catch (TaskFailException $e) {
				
				// Log the exception
				$this->logger->error($e->getMessage());
				throw $e;
				
			} finally {
				// Always cancel the alarm to prevent it from triggering after task completion
				// Setting alarm to 0 cancels any pending alarm
				pcntl_alarm(0);
			}
		}
	}