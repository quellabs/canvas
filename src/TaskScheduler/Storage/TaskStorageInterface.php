<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Storage;
	
	interface TaskStorageInterface {
		
		/**
		 * Marks the task as busy
		 * @param string $taskName
		 * @param \DateTime $dateTime
		 * @return void
		 */
		public function markAsBusy(string $taskName, \DateTime $dateTime): void;
		
		/**
		 * Mark a task as done
		 * @param string $taskName
		 * @param \DateTime $dateTime
		 * @return void
		 */
		public function markAsDone(string $taskName, \DateTime $dateTime): void;
		
		/**
		 * Returns true if the task is currently busy, false if not
		 * @param string $taskName
		 * @return bool
		 */
		public function isBusy(string $taskName): bool;
	}