<?php
	
	namespace Quellabs\Canvas\TaskScheduler;
	
	use Cron\CronExpression;
	use Psr\Log\LoggerInterface;
	use Psr\Log\NullLogger;
	use Quellabs\Canvas\TaskScheduler\Runner\TaskRunnerFactory;
	use Quellabs\Canvas\TaskScheduler\Storage\TaskStorageInterface;
	use Quellabs\Contracts\TaskScheduler\TaskInterface;
	use Quellabs\Contracts\TaskScheduler\TaskTimeoutException;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Scanner\ComposerScanner;
	
	class TaskScheduler {
		
		private TaskStorageInterface $storage;
		private LoggerInterface $logger;
		
		/**
		 * @var array<TaskInterface> List of tasks to perform
		 */
		private array $tasks = [];
		
		/**
		 * TaskScheduler constructor
		 * @param TaskStorageInterface $storage
		 * @param LoggerInterface|null $logger
		 */
		public function __construct(
			TaskStorageInterface $storage,
			?LoggerInterface     $logger = null
		) {
			$this->storage = $storage;
			$this->logger = $logger ?? new NullLogger();
			
			// Scan for tasks
			$this->scanForTasks();
		}
		
		/**
		 * Run all due tasks and return the task results
		 * @return array<TaskResult> Collection of results from all executed tasks
		 */
		public function run(): array {
			$results = [];
			
			// Execute each task that is currently due for execution
			// getDueTasks() handles all filtering (enabled, scheduled, not busy)
			foreach ($this->getDueTasks() as $task) {
				// Run each task individually with full error isolation
				// Failed tasks don't prevent other tasks from executing
				$results[] = $this->runTask($task);
			}
			
			// Return all execution results for external monitoring/reporting
			// Allows calling code to analyze success rates, timing, and failures
			return $results;
		}
		
		/**
		 * Returns a list of tasks
		 * @return TaskInterface[]
		 */
		public function getTaskList(): array {
			return $this->tasks;
		}
		
		/**
		 * Run a specific task with timeout handling
		 * @param TaskInterface $task The task to execute
		 * @return TaskResult Result object containing execution status, duration, and any errors
		 */
		private function runTask(TaskInterface $task): TaskResult {
			// Capture task name
			$taskName = $task->getName();
			
			// Capture start time for performance metrics
			// Using microtime(true) for high-precision timing measurement
			$startTime = microtime(true);
			
			try {
				// Log task initiation for debugging and monitoring
				$this->logger->info("Starting task: {$taskName}");
				
				// Create appropriate timeout strategy based on task configuration
				// The factory pattern allows different timeout implementations (process timeout, etc.)
				$taskRunner = TaskRunnerFactory::create($task->getTimeout(), $this->logger);
				
				// Mark task as busy in storage to prevent concurrent execution
				// This creates a distributed lock across multiple scheduler instances
				$this->storage->markAsBusy($taskName, new \DateTime());
				
				// Execute the actual task logic with timeout protection
				// The runner handles timeout enforcement and process management
				$taskRunner->run($task);
				
				// Mark task as completed in storage
				// This releases the distributed lock and updates task status
				$this->storage->markAsDone($taskName, new \DateTime());
				
				// Calculate execution duration for performance monitoring
				// Convert to milliseconds for human-readable logging
				$duration = round((microtime(true) - $startTime) * 1000);
				$this->logger->info("Task {$taskName} completed successfully in {$duration}ms");
				
				// Return a successful result with timing information
				return new TaskResult($task, true, $duration);
				
			} catch (TaskTimeoutException $e) {
				// Handle timeout-specific exceptions from the task runner
				// TaskException indicates the task exceeded its allowed execution time
				$duration = round((microtime(true) - $startTime) * 1000);
				$this->logger->warning("{$taskName} timeout: {$e->getMessage()}");
				
				// Call timeout-specific handler and return result
				return $this->handleTaskFailure($task, $e, $duration, 'onTimeout', 'timeout handler');
				
			} catch (\Exception $e) {
				// Handle all other exceptions (task logic errors, system failures, etc.)
				$duration = round((microtime(true) - $startTime) * 1000);
				
				// Call general failure handler and return result
				return $this->handleTaskFailure($task, $e, $duration, 'onFailure', 'failure handler');

			} finally {
				// Ensure the task is always marked as done, regardless of success or failure.
				// This is critical for releasing distributed locks and preventing deadlocks
				// The finally block guarantees execution even if exceptions occur above
				$this->storage->markAsDone($taskName, new \DateTime());
			}
		}
		
		/**
		 * Handle task failure by calling the appropriate handler and returning result
		 * @param TaskInterface $task The failed task
		 * @param \Exception $exception The exception that caused the failure
		 * @param float $duration Task execution duration in milliseconds
		 * @param string $handlerMethod Name of the handler method to call ('onTimeout' or 'onFailure')
		 * @param string $handlerType Human-readable handler type for error logging
		 * @return TaskResult Failed task result with exception details
		 */
		private function handleTaskFailure(
			TaskInterface $task,
			\Exception $exception,
			float $duration,
			string $handlerMethod,
			string $handlerType
		): TaskResult {
			// Attempt to call the task's custom handler if it exists
			// This allows tasks to perform cleanup, send notifications, or other recovery actions
			try {
				$task->$handlerMethod($exception);
			} catch (\Exception $handlerException) {
				// If the handler itself fails, log the secondary error
				// This prevents handler failures from masking the original error
				// We continue execution to ensure the original failure is still properly reported
				$this->logger->error("Task {$handlerType} also failed: " . $handlerException->getMessage());
			}
			
			// Return failed result with the original exception for debugging
			// The TaskResult preserves exception details for calling code analysis
			return new TaskResult($task, false, $duration, $exception);
		}
		
		/**
		 * Make a list of tasks to perform
		 * @return void
		 */
		private function scanForTasks(): void {
			// Add a Composer-based scanner to look for task implementations
			// This scans for classes in the "task_scheduler" section of composer.json
			$discover = new Discover();
			$discover->addScanner(new ComposerScanner("task-scheduler", "discover", $this->logger));
			$discover->discover();
			
			// Build a list of tasks; filter out everything that does not implement TaskInterface
			foreach ($discover->getProviders() as $provider) {
				// Check if the discovered class implements the TaskInterface
				// Only include classes that properly implement the task contract
				if (!is_subclass_of($provider, TaskInterface::class)) {
					$providerClass = get_class($provider);
					$this->logger->warning("Skipping task provider '{$providerClass}' - does not implement TaskInterface");
					continue;
				}
				
				// Add valid task class to our result array
				$this->tasks[] = $provider;
			}
		}
		
		/**
		 * Get tasks that are due to run right now
		 * @return array<TaskInterface> Array of tasks ready for execution
		 */
		protected function getDueTasks(): array {
			$result = [];
			
			// Iterate through all discovered tasks to check their execution eligibility
			foreach ($this->tasks as $task) {
				// Skip disabled tasks to respect configuration-based task control
				// This allows tasks to be temporarily disabled without removing them
				if (!$task->enabled()) {
					continue;
				}
				
				// Extract task identifier for logging and storage operations
				$taskName = $task->getName();
				
				// Parse the task's cron schedule expression
				// Supports standard cron format: minute hour day month day-of-week
				$cron = new CronExpression($task->getSchedule());
				
				// Check if task meets both timing and availability criteria:
				// 1. isDue() - Current time matches the cron schedule
				// 2. !isBusy() - Task is not already running (prevents duplicate execution)
				if ($cron->isDue() && !$this->storage->isBusy($taskName)) {
					// Task is ready for execution - add to result set
					$result[] = $task;
				}
				
				// Note: Tasks that are due but busy will be picked up on the next scheduler run
				// when they complete, ensuring no executions are permanently missed
			}
			
			return $result;
		}
	}