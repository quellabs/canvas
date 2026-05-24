<?php
	
	namespace Quellabs\Canvas\TaskScheduler;
	
	/**
	 * Base interface for all executable jobs in the TaskScheduler system.
	 * This is the foundation contract shared by all consumers (cron, queue, etc.).
	 */
	interface JobInterface {
		
		/**
		 * Execute the job
		 * @return void
		 */
		public function handle(): void;
		
		/**
		 * Returns the maximum execution time in seconds (0 = no timeout)
		 * @return int
		 */
		public function getTimeout(): int;
		
		/**
		 * Returns the maximum number of retries on failure
		 * @return int
		 */
		public function getMaxRetries(): int;
	}