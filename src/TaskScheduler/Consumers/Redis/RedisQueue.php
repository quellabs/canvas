<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Redis;
	
	use Predis\Client;
	use Quellabs\Canvas\TaskScheduler\JobInterface;
	use Quellabs\Canvas\TaskScheduler\QueueableInterface;
	
	/**
	 * Redis-backed job queue.
	 * Uses a list as the pending queue (RPUSH/BLPOP) and a separate list
	 * as the failed job store for jobs that exhaust their retry allowance.
	 *
	 * Key layout:
	 *   {prefix}:queue:{name}         — pending jobs (list)
	 *   {prefix}:failed:{name}        — failed jobs (list)
	 *   {prefix}:reserved:{name}      — currently executing job (string, single slot)
	 */
	class RedisQueue {
		
		private Client $redis;
		private string $queueName;
		private string $prefix;
		
		/**
		 * RedisQueue constructor
		 * @param Client $redis Predis client instance
		 * @param string $queueName Name of the queue
		 * @param string $prefix Key prefix to namespace queue keys
		 */
		public function __construct(
			Client $redis,
			string $queueName = 'default',
			string $prefix = 'canvas'
		) {
			$this->redis = $redis;
			$this->queueName = $queueName;
			$this->prefix = $prefix;
		}
		
		/**
		 * Push a job onto the queue
		 * @param JobInterface $job
		 * @return void
		 */
		public function push(QueueableInterface $job): void {
			$envelope = JobEnvelope::fromJob($job);
			$this->redis->rpush($this->pendingKey(), [$envelope->toJson()]);
		}
		
		/**
		 * Block until a job is available, then return it.
		 * Returns null if the timeout elapses with no job available.
		 * @param int $timeout Seconds to block waiting for a job (0 = block forever)
		 * @return JobEnvelope|null
		 */
		public function pop(int $timeout = 5): ?JobEnvelope {
			// BLPOP returns [key, value] or null on timeout
			$result = $this->redis->blpop([$this->pendingKey()], $timeout);
			
			if ($result === null) {
				return null;
			}
			
			try {
				$envelope = JobEnvelope::fromJson($result[1]);
			} catch (\InvalidArgumentException $e) {
				// Malformed envelope — discard and return null, worker will loop again
				return null;
			}
			
			// Store in reserved slot so we can detect crashed workers
			$this->redis->set($this->reservedKey($envelope->id), $result[1]);
			
			return $envelope;
		}
		
		/**
		 * Acknowledge successful job execution and remove from reserved slot
		 * @param JobEnvelope $envelope
		 * @return void
		 */
		public function acknowledge(JobEnvelope $envelope): void {
			$this->redis->del([$this->reservedKey($envelope->id)]);
		}
		
		/**
		 * Handle a failed job — retry if attempts remain, otherwise move to failed list
		 * @param JobEnvelope $envelope
		 * @return void
		 */
		public function fail(JobEnvelope $envelope): void {
			// Remove from reserved slot regardless of retry decision
			$this->redis->del([$this->reservedKey($envelope->id)]);
			
			$incremented = $envelope->withIncrementedAttempts();
			
			if ($incremented->hasExceededMaxRetries()) {
				// Move to failed list for inspection
				$this->redis->rpush($this->failedKey(), [$incremented->toJson()]);
			} else {
				// Requeue with incremented attempt count
				$this->redis->rpush($this->pendingKey(), [$incremented->toJson()]);
			}
		}
		
		/**
		 * Returns the number of jobs currently pending
		 * @return int
		 */
		public function size(): int {
			return $this->redis->llen($this->pendingKey());
		}
		
		/**
		 * Returns the number of jobs in the failed list
		 * @return int
		 */
		public function failedCount(): int {
			return $this->redis->llen($this->failedKey());
		}
		
		/**
		 * Returns the Redis key for the pending queue
		 * @return string
		 */
		private function pendingKey(): string {
			return "{$this->prefix}:queue:{$this->queueName}";
		}
		
		/**
		 * Returns the Redis key for the failed list
		 * @return string
		 */
		private function failedKey(): string {
			return "{$this->prefix}:failed:{$this->queueName}";
		}
		
		/**
		 * Returns the Redis key for a reserved job slot
		 * @param string $jobId
		 * @return string
		 */
		private function reservedKey(string $jobId): string {
			return "{$this->prefix}:reserved:{$this->queueName}:{$jobId}";
		}
	}