<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Cron\Runner;
	
	use Psr\Log\LoggerInterface;
	use Quellabs\Canvas\TaskScheduler\JobInterface;
	use Quellabs\Contracts\TaskScheduler\TaskFailException;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	
	/**
	 * Runner strategy using PCNTL (Process Control) functions to enforce execution
	 * time limits on jobs. Uses SIGALRM signals to interrupt job execution when
	 * the specified timeout period is exceeded.
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
		 * Constructor - initializes the strategy with a timeout and logger instance.
		 * @param int $timeout Maximum execution time in seconds
		 * @param LoggerInterface $logger Logger for debugging and error reporting
		 */
		public function __construct(int $timeout, LoggerInterface $logger) {
			$this->timeout = $timeout;
			$this->logger  = $logger;
		}
		
		/**
		 * Executes a job with a specified timeout using PCNTL alarm signals
		 * @param JobInterface $job The job to execute
		 * @throws \RuntimeException If PCNTL functions are not available
		 * @throws TaskTimeoutException If the job execution exceeds the timeout
		 * @throws \Exception
		 */
		public function run(JobInterface $job): void {
			// Check if required PCNTL functions are available on this system
			if (!function_exists('pcntl_fork') || !function_exists('pcntl_alarm')) {
				throw new \RuntimeException('PCNTL functions not available');
			}
			
			// Set up signal handler for SIGALRM to throw timeout exception
			pcntl_signal(SIGALRM, function () use ($job): void {
				throw new TaskTimeoutException("Job " . get_class($job) . " timed out");
			});
			
			// Set the alarm to trigger after the specified timeout duration
			pcntl_alarm($this->timeout);
			
			try {
				// Execute the job — will be interrupted by SIGALRM if timeout is exceeded
				$job->handle();
				
			} catch (TaskFailException $e) {
				// Log the exception
				$this->logger->error($e->getMessage());
				throw $e;
				
			} finally {
				// Always cancel the alarm to prevent it from triggering after job completion
				// Setting alarm to 0 cancels any pending alarm
				pcntl_alarm(0);
			}
		}
	}
