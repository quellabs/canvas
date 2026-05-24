<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Redis;
	
	use Predis\Client;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Contracts\TaskScheduler\ConsumerInterface;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * Redis queue consumer.
	 * Discovered via the "task-scheduler" Composer family and selected
	 * by Sculpt when --consumer=redis is specified.
	 */
	class RedisConsumer implements ConsumerInterface {
		
		/**
		 * @var array<string, mixed>
		 */
		private array $config = [];
		
		/**
		 * Returns the identifier used to select this consumer via CLI
		 * @return string
		 */
		public static function getName(): string {
			return 'redis';
		}
		
		/**
		 * Returns metadata about this consumer for discovery
		 * @return array<string, mixed>
		 */
		public static function getMetadata(): array {
			return [
				'name'        => self::getName(),
				'description' => 'Redis-backed job queue consumer',
			];
		}
		
		/**
		 * Returns the configuration
		 * @return array<string, mixed>
		 */
		public function getConfig(): array {
			return $this->config;
		}
		
		/**
		 * Sets configuration
		 * @param array<string, mixed> $config
		 * @return void
		 */
		public function setConfig(array $config): void {
			$this->config = $config;
		}
		
		/**
		 * Start the Redis consumer and begin processing jobs.
		 * Loads its own configuration from app.php.
		 * @return void
		 */
		public function run(): void {
			$projectRoot = ComposerUtils::getProjectRoot();
			
			if (file_exists($projectRoot . '/config/app.php')) {
				$appConfig = require $projectRoot . '/config/app.php';
			} else {
				$appConfig = [];
			}
			
			$queueName   = $appConfig['queue_name'] ?? 'default';
			$maxJobs     = $appConfig['queue_max_jobs'] ?? 500;
			$timeout     = $appConfig['queue_timeout'] ?? 5;
			$prefix      = $appConfig['queue_prefix'] ?? 'canvas';
			$redisConfig = $appConfig['redis'] ?? [];
			
			$redis = new Client([
				'scheme' => $redisConfig['scheme'] ?? 'tcp',
				'host'   => $redisConfig['host'] ?? '127.0.0.1',
				'port'   => $redisConfig['port'] ?? 6379,
			]);
			
			$kernel    = new Kernel($appConfig);
			$container = $kernel->getDependencyInjector();
			$queue     = new RedisQueue($redis, $queueName, $prefix);
			$worker    = new RedisWorker($queue, $container);
			
			$worker->work($maxJobs, $timeout);
		}
	}