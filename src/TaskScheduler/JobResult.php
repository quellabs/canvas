<?php
	
	namespace Quellabs\Canvas\TaskScheduler;
	
	/**
	 * Represents the result of a job execution
	 */
	readonly class JobResult {
		
		public JobInterface $job;
		public bool $success;
		public int $duration;
		public ?\Exception $exception;
		
		public function __construct(
			JobInterface $job,
			bool         $success,
			int          $duration = 0,
			?\Exception  $exception = null
		) {
			$this->job       = $job;
			$this->success   = $success;
			$this->duration  = $duration;
			$this->exception = $exception;
		}
		
		/**
		 * Returns true if the job executed successfully
		 * @return bool
		 */
		public function isSuccess(): bool {
			return $this->success;
		}
		
		/**
		 * Returns the exception that caused failure, or null on success
		 * @return \Exception|null
		 */
		public function getException(): ?\Exception {
			return $this->exception;
		}
		
		/**
		 * Returns the execution duration in milliseconds
		 * @return int
		 */
		public function getDuration(): int {
			return $this->duration;
		}
	}