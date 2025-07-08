<?php
	
	namespace Quellabs\Canvas\TaskScheduler;
	
	use Quellabs\Contracts\TaskScheduler\TaskInterface;
	
	/**
	 * Task execution result
	 */
	readonly class TaskResult {
		public TaskInterface $task;
		public bool $success;
		public int $duration;
		public ?\Exception $exception;
		
		public function __construct(
			TaskInterface $task,
			bool          $success,
			int           $duration = 0,
			?\Exception   $exception = null
		) {
			$this->duration = $duration;
			$this->exception = $exception;
			$this->success = $success;
			$this->task = $task;
		}
		
		public function getTaskName(): string {
			return $this->task->getName();
		}
		
		public function isSuccess(): bool {
			return $this->success;
		}
		
		public function getException(): ?\Exception {
			return $this->exception;
		}
		
		public function getDuration(): float {
			return $this->duration;
		}
	}