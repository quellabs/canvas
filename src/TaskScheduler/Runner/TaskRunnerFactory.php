<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Runner;
	
	use Psr\Log\LoggerInterface;
	
	/**
	 * This factory determines which timeout strategy implementation to use
	 * based on the availability of system functions. It prioritizes the
	 * PCNTL-based strategy when available, falling back to a process-based
	 * strategy otherwise.
	 */
	class TaskRunnerFactory {
		
		/**
		 * Creates and returns an appropriate timeout strategy instance.
		 *
		 * The factory uses a priority-based selection:
		 * 1. NoTimeoutStrategy - when timeout is 0 (no timeout needed)
		 * 2. PcntlTimeoutStrategy - when PCNTL functions are available (preferred)
		 * 3. ProcessTimeoutStrategy - fallback for systems without PCNTL support
		 *
		 * @param int $timeout The timeout value in seconds (0 means no timeout)
		 * @param LoggerInterface $logger Logger instance for the timeout strategy
		 * @return TaskRunnerInterface The created timeout strategy instance
		 */
		public static function create(int $timeout, LoggerInterface $logger): TaskRunnerInterface {
			// Return no-timeout strategy when timeout is disabled (0 seconds)
			if ($timeout == 0) {
				return new StrategyNoTimeout($timeout, $logger);
			}
			
			// Prefer PCNTL-based strategy if system supports process control functions
			// PCNTL provides more efficient signal-based timeout handling
			if (function_exists('pcntl_fork') && function_exists('pcntl_alarm')) {
				return new StrategyPcntl($timeout, $logger);
			}
			
			// Use process-based timeout as fallback for systems without PCNTL support
			// This strategy likely uses external process monitoring or polling
			return new StrategyTimeout($timeout, $logger);
		}
	}