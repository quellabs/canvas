<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Consumers\Redis;
	
	use Predis\Client;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Sculpt\BaseCommand;
	use Quellabs\Sculpt\ConfigurationManager;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * Sculpt command that starts a Redis queue worker process.
	 *
	 * Usage:
	 *   php sculpt queue:work
	 *   php sculpt queue:work --queue=default --max-jobs=500 --timeout=5
	 *
	 * Intended to run under Supervisord which restarts it automatically
	 * after it exits (either from --max-jobs limit or a stop signal).
	 */
	class QueueWorkCommand extends BaseCommand {
		
		/**
		 * Returns the signature of this command
		 * @return string
		 */
		public function getSignature(): string {
			return "queue:work";
		}
		
		/**
		 * Returns a brief description of what this command is for
		 * @return string
		 */
		public function getDescription(): string {
			return "Start a Redis queue worker process";
		}
		
		/**
		 * Execute the queue worker
		 * @param ConfigurationManager $config
		 * @return int Exit code
		 */
		public function execute(ConfigurationManager $config): int {
			$projectRoot = ComposerUtils::getProjectRoot();
			
			// Load app config for Redis connection details and queue settings
			$appConfig = file_exists($projectRoot . '/config/app.php')
				? require $projectRoot . '/config/app.php'
				: [];
			
			// Read CLI options with fallback to app config then defaults
			$queueName = $config->getAsString('queue', $appConfig['queue_name'] ?? 'default');
			$maxJobs   = $config->getAsInt('max-jobs', $appConfig['queue_max_jobs'] ?? 500);
			$timeout   = $config->getAsInt('timeout', $appConfig['queue_timeout'] ?? 5);
			$prefix    = $appConfig['queue_prefix'] ?? 'canvas';
			
			// Build Redis connection parameters from app config
			$redisConfig = $appConfig['redis'] ?? [];
			
			// Connect to Redis
			$redis = new Client([
				'scheme' => $redisConfig['scheme'] ?? 'tcp',
				'host'   => $redisConfig['host']   ?? '127.0.0.1',
				'port'   => $redisConfig['port']   ?? 6379,
			]);
			
			// Bootstrap the Kernel to get the DI container
			$kernel = new Kernel($appConfig);
			$container = $kernel->getDependencyInjector();
			
			// Build queue and worker
			$queue  = new RedisQueue($redis, $queueName, $prefix);
			$worker = new RedisWorker($queue, $container);
			
			// Run until max jobs reached or signal received
			$worker->work($maxJobs, $timeout);
			
			return 0;
		}
	}