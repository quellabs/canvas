<?php
	
	namespace Quellabs\Canvas\Scheduler\Cron;
	
	use Quellabs\Contracts\Scheduler\TaskTimeoutException;
	
	/**
	 * Abstract base class for scheduled tasks
	 *
	 * This abstract class provides a foundation for creating scheduled tasks in the Canvas Task Scheduler.
	 * It implements both TaskInterface and ProviderInterface, providing default implementations for
	 * common task functionality while requiring concrete classes to implement the core task logic.
	 *
	 * Key features:
	 * - Automatic task naming based on class name
	 * - Default timeout and enablement settings
	 * - Extensible error and timeout handling
	 * - Configuration management through ProviderInterface
	 */
	abstract class AbstractTask implements TaskInterface {
		
		// ****************************************
		// TaskInterface methods
		// ****************************************
		
		/**
		 * Task name defaults to class name in kebab-case
		 * @return string The kebab-case task name
		 */
		public function getName(): string {
			// Fetch class name using reflection to get the short name (without namespace)
			// This ensures we only get the actual class name, not the full qualified name
			$className = (new \ReflectionClass($this))->getShortName();
			
			// Pattern matches a lowercase letter followed by an uppercase letter and inserts hyphen
			$replacedClassName = preg_replace('/([a-z0-9])([A-Z])/', '$1-$2', $className);
			
			// Pattern matches a lowercase letter followed by an uppercase letter and inserts hyphen
			if ($replacedClassName === null) {
				throw new \RuntimeException("Can't preg_replace $className");
			}
			
			// Convert to lowercase
			return strtolower($replacedClassName);
		}
		
		/**
		 * This method determines whether the task should be executed when its schedule triggers.
		 * The default implementation always returns true, meaning the task will run every
		 * time it's scheduled.
		 *
		 * Default: always run when scheduled
		 *
		 * Override this method to implement conditional execution logic, such as
		 * - Checking system load or resource availability
		 * - Validating prerequisites or dependencies
		 * - Implementing feature flags or maintenance mode checks
		 * - Time-based conditions beyond the schedule
		 *
		 * @return bool True if the task should execute, false otherwise
		 */
		public function enabled(): bool {
			return true;
		}
		
		/**
		 * Sets the maximum execution time for the task in seconds.
		 * The default of 300 seconds (5 minutes) should be sufficient for most tasks.
		 *
		 * Default: 5-minute timeout
		 *
		 * Override this method to set a custom timeout based on the task's expected
		 * execution time. Consider factors like:
		 * - Network operations and external API calls
		 * - Database queries and data processing volume
		 * - File I/O operations
		 * - Computational complexity
		 *
		 * @return int Timeout in seconds (300 = 5 minutes)
		 */
		public function getTimeout(): int {
			return 300; // 5 minutes in seconds
		}
		
		/**
		 * Returns the maximum number of retries on failure.
		 * Cron tasks default to 0 — the scheduler handles retry timing via the cron schedule itself.
		 * @return int
		 */
		public function getMaxRetries(): int {
			return 0;
		}
		
		/**
		 * This method is called when the task execution throws an exception.
		 * The default implementation does nothing, allowing the scheduler to handle
		 * the failure using its standard error handling mechanisms.
		 *
		 * Default: no special failure handling
		 *
		 * Override this method to implement custom error handling logic such as:
		 * - Logging specific error details with context
		 * - Sending notifications to administrators or monitoring systems
		 * - Performing cleanup operations (closing connections, releasing resources)
		 * - Retrying with different parameters or fallback strategies
		 * - Recording failure metrics for monitoring and analysis
		 *
		 * @param \Exception $exception The exception that caused the task to fail
		 */
		public function onFailure(\Exception $exception): void {
			// Override for custom error handling
			// Default implementation intentionally empty - scheduler handles basic error logging
		}
		
		/**
		 * This method is called when the task execution exceeds the configured timeout.
		 * The default implementation does nothing, allowing the scheduler to handle
		 * the timeout using its standard timeout handling mechanisms.
		 *
		 * Default: no special timeout handling
		 *
		 * Override this method to implement custom timeout handling logic such as:
		 * - Logging timeout details with execution context
		 * - Sending alerts to administrators or monitoring systems
		 * - Performing partial cleanup of incomplete operations
		 * - Adjusting timeout for future runs based on execution patterns
		 * - Recording timeout metrics for performance analysis
		 *
		 * @param TaskTimeoutException $exception The timeout exception that was thrown
		 */
		public function onTimeout(TaskTimeoutException $exception): void {
			// Override for custom timeout handling
			// Default implementation intentionally empty - scheduler handles basic timeout logging
		}
		
		// ****************************************
		// ProviderInterface methods
		// ****************************************
		
		/**
		 * Get metadata about this task provider
		 * @return array<string, mixed> Associative array of metadata key-value pairs
		 */
		public static function getMetadata(): array {
			return [];
		}
		
		/**
		 * Get current configuration
		 * @return array<string, mixed> Current configuration values
		 */
		public function getConfig(): array {
			return [];
		}
		
		/**
		 * Set configuration values
		 * @param array<string, mixed> $config Configuration values to set
		 * @return void
		 */
		public function setConfig(array $config): void {
			// Override to handle configuration storage and validation
		}
		
		// ****************************************
		// Abstract methods. Fill these in
		// ****************************************
		
		/**
		 * Get task description
		 * @return string Human-readable task description
		 */
		abstract public function getDescription(): string;
		
		/**
		 * Main task execution logic
		 *
		 * This method contains the core functionality of the task. It will be called
		 * by the scheduler when the task is due to run and is enabled.
		 *
		 * Implementation should:
		 * - Perform the task's primary function
		 * - Handle expected errors gracefully
		 * - Throw exceptions for unrecoverable failures
		 * - Complete within the configured timeout period
		 * - Be idempotent when possible (safe to run multiple times)
		 *
		 * @throws \Exception When task execution fails and cannot be recovered
		 */
		abstract public function handle(): void;
		
		/**
		 * Get cron schedule expression
		 *
		 * Returns the cron expression or shortcut that defines when this task should run.
		 * The scheduler uses this to determine the next execution time.
		 *
		 * Examples:
		 * - '0 8 * * *' (daily at 8 AM)
		 * - '0 0 1 * *' (first day of each month)
		 * - '0 9-17 * * 1-5' (hourly during business hours, weekdays only)
		 *
		 * @return string Cron expression defining the schedule
		 */
		abstract public function getSchedule(): string;
	}