<?php
	
	namespace Quellabs\Canvas\Scheduler\Storage;
	
	/**
	 * Interface for job execution state storage.
	 * Implementations provide distributed locking to prevent concurrent execution
	 * of the same job across multiple scheduler instances.
	 */
	interface JobStorageInterface {
		
		/**
		 * Mark a job as busy (acquire execution lock)
		 * @param string $jobName
		 * @param \DateTime $dateTime
		 * @return void
		 */
		public function markAsBusy(string $jobName, \DateTime $dateTime): void;
		
		/**
		 * Mark a job as done (release execution lock)
		 * @param string $jobName
		 * @param \DateTime $dateTime
		 * @return void
		 */
		public function markAsDone(string $jobName, \DateTime $dateTime): void;
		
		/**
		 * Returns true if the job is currently executing
		 * @param string $jobName
		 * @return bool
		 */
		public function isBusy(string $jobName): bool;
	}
