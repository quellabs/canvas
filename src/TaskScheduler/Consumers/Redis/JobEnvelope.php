<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Redis;
	
	use Quellabs\Canvas\TaskScheduler\JobInterface;
	use Quellabs\Canvas\TaskScheduler\QueueableInterface;
	
	/**
	 * Represents a job as it travels through the Redis queue.
	 * Wraps the job class name, payload, and execution metadata
	 * in a structure that can be serialized to and from JSON.
	 *
	 * @phpstan-type EnvelopeData array{
	 *     id: string,
	 *     class: class-string<JobInterface>,
	 *     payload: array<string, mixed>,
	 *     attempts: int,
	 *     max_retries: int,
	 *     timeout: int,
	 *     queued_at: int
	 * }
	 */
	class JobEnvelope {
		
		/**
		 * @var string Unique identifier for this job instance
		 */
		public readonly string $id;
		
		/**
		 * @var class-string<JobInterface> Fully qualified job class name
		 */
		public readonly string $class;
		
		/**
		 * @var array<string, mixed> Constructor parameters to reconstruct the job
		 */
		public readonly array $payload;
		
		/**
		 * @var int Number of times this job has been attempted
		 */
		public readonly int $attempts;
		
		/**
		 * @var int Maximum number of retry attempts before moving to failed list
		 */
		public readonly int $maxRetries;
		
		/**
		 * @var int Maximum execution time in seconds (0 = no timeout)
		 */
		public readonly int $timeout;
		
		/**
		 * @var int Unix timestamp when the job was queued
		 */
		public readonly int $queuedAt;
		
		/**
		 * JobEnvelope constructor
		 * @param class-string<JobInterface> $class
		 * @param array<string, mixed> $payload
		 * @param int $attempts
		 * @param int $maxRetries
		 * @param int $timeout
		 * @param string|null $id
		 * @param int|null $queuedAt
		 */
		public function __construct(
			string  $class,
			array   $payload,
			int     $attempts = 0,
			int     $maxRetries = 3,
			int     $timeout = 60,
			?string $id = null,
			?int    $queuedAt = null
		) {
			$this->class = $class;
			$this->payload = $payload;
			$this->attempts = $attempts;
			$this->maxRetries = $maxRetries;
			$this->timeout = $timeout;
			$this->id = $id ?? $this->generateId();
			$this->queuedAt = $queuedAt ?? time();
		}
		
		/**
		 * Create an envelope from a QueueableInterface instance
		 * @param QueueableInterface $job
		 * @return self
		 */
		public static function fromJob(QueueableInterface $job): self {
			return new self(
				class: get_class($job),
				payload: $job->getPayload(),
				maxRetries: $job->getMaxRetries(),
				timeout: $job->getTimeout()
			);
		}
		
		/**
		 * Reconstruct an envelope from a JSON string popped from Redis
		 * @param string $json
		 * @return self
		 * @throws \InvalidArgumentException If the JSON is malformed or missing required fields
		 */
		public static function fromJson(string $json): self {
			$data = json_decode($json, true);
			
			if (!is_array($data)) {
				throw new \InvalidArgumentException("Invalid job envelope JSON: failed to decode");
			}
			
			// Validate required fields
			foreach (['id', 'class', 'payload', 'attempts', 'max_retries', 'timeout', 'queued_at'] as $field) {
				if (!array_key_exists($field, $data)) {
					throw new \InvalidArgumentException("Invalid job envelope JSON: missing field '{$field}'");
				}
			}
			
			if (!class_exists($data['class'])) {
				throw new \InvalidArgumentException("Job class '{$data['class']}' does not exist");
			}
			
			return new self(
				class: $data['class'],
				payload: $data['payload'],
				attempts: (int)$data['attempts'],
				maxRetries: (int)$data['max_retries'],
				timeout: (int)$data['timeout'],
				id: $data['id'],
				queuedAt: (int)$data['queued_at']
			);
		}
		
		/**
		 * Serialize the envelope to a JSON string for storage in Redis
		 * @return string
		 */
		public function toJson(): string {
			return json_encode([
				'id'          => $this->id,
				'class'       => $this->class,
				'payload'     => $this->payload,
				'attempts'    => $this->attempts,
				'max_retries' => $this->maxRetries,
				'timeout'     => $this->timeout,
				'queued_at'   => $this->queuedAt,
			], JSON_THROW_ON_ERROR);
		}
		
		/**
		 * Return a copy of this envelope with the attempt count incremented
		 * @return self
		 */
		public function withIncrementedAttempts(): self {
			return new self(
				class: $this->class,
				payload: $this->payload,
				attempts: $this->attempts + 1,
				maxRetries: $this->maxRetries,
				timeout: $this->timeout,
				id: $this->id,
				queuedAt: $this->queuedAt
			);
		}
		
		/**
		 * Returns true if the job has exhausted its retry allowance
		 * @return bool
		 */
		public function hasExceededMaxRetries(): bool {
			return $this->attempts >= $this->maxRetries;
		}
		
		/**
		 * Generate a unique job ID
		 * @return string
		 */
		private function generateId(): string {
			return sprintf(
				'%s-%s',
				bin2hex(random_bytes(8)),
				time()
			);
		}
	}