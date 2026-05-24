<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Canvas\TaskScheduler\Consumers\Cron\TaskScheduler;
	use Quellabs\Canvas\TaskScheduler\Storage\FileJobStorage;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * This command discovers and executes all scheduled tasks in the system.
	 * It uses a file-based storage system to persist task scheduling information.
	 */
	class SchedulerRunCommand extends RoutesBase {
		
		/**
		 * Returns the signature of this command
		 * @return string The command signature "schedule:run"
		 */
		public function getSignature(): string {
			return "schedule:run";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string A human-readable description of the command
		 */
		public function getDescription(): string {
			return "Executes all scheduled tasks that are due to run";
		}
		
		/**
		 * Executes the scheduled task runner
		 *
		 * This method performs the main functionality of the command:
		 * 1. Loads application configuration to resolve the tasks directory
		 * 2. Creates a task scheduler with file-based storage
		 * 3. Runs all discovered scheduled tasks
		 *
		 * @param ConfigurationManager $config The application configuration manager
		 * @return int Exit code (0 for success, non-zero for failure)
		 */
		public function execute(ConfigurationManager $config): int {
			$projectRoot = ComposerUtils::getProjectRoot();
			
			// Load app config to resolve the tasks directory path
			if (file_exists($projectRoot . '/config/app.php')) {
				$appConfig = require $projectRoot . '/config/app.php';
			} else {
				$appConfig = [];
			}
			
			// Load path from config
			$tasksPath = $appConfig['task_scheduler_directory'] ?? $projectRoot . '/src/Tasks';
			
			// Create a task scheduler instance with file-based storage
			// The storage directory is set to {project_root}/storage/task-scheduler
			$scheduler = new TaskScheduler(
				new FileJobStorage($projectRoot . "/storage/task-scheduler"),
				$tasksPath
			);
			
			// Execute all discovered scheduled tasks
			$scheduler->run();
			
			// Return success status code
			return 0;
		}
	}