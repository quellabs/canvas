<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Discover\Discover;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Canvas\TaskScheduler\TaskScheduler;
	use Quellabs\Canvas\TaskScheduler\Storage\FileTaskStorage;
	
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
		 * 1. Initializes the project discovery service
		 * 2. Creates a task scheduler with file-based storage
		 * 3. Runs all discovered scheduled tasks
		 *
		 * @param ConfigurationManager $config The application configuration manager
		 * @return int Exit code (0 for success, non-zero for failure)
		 */
		public function execute(ConfigurationManager $config): int {
			// Initialize the project discovery service to locate the project root
			$discover = new Discover();
			
			// Create a task scheduler instance with file-based storage
			// The storage directory is set to {project_root}/storage/task-scheduler
			$scheduler = new TaskScheduler(
				new FileTaskStorage($discover->getProjectRoot() . "/storage/task-scheduler")
			);
			
			// Execute all discovered scheduled tasks
			$scheduler->run();
			
			// Return success status code
			return 0;
		}
	}