<?php
	
	namespace Quellabs\Canvas\TaskScheduler;
	
	/**
	 * Extends JobInterface for jobs that can be dispatched to a queue.
	 * Adds payload serialization so queue consumers can reconstruct the job
	 * at execution time using the DI container.
	 */
	interface QueueableInterface extends JobInterface {
		
		/**
		 * Return the constructor parameters to serialize when dispatching.
		 * Keys must match the job's constructor parameter names exactly,
		 * as they are passed directly to the DI container's make() method.
		 * @return array<string, mixed>
		 */
		public function getPayload(): array;
	}