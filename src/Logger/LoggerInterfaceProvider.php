<?php
	
	namespace Quellabs\Canvas\Logger;
	
	use Quellabs\Support\ComposerUtils;
	use Monolog\Handler\ErrorLogHandler;
	use Monolog\Handler\RotatingFileHandler;
	use Monolog\Handler\StreamHandler;
	use Monolog\Level;
	use Monolog\Logger;
	use Psr\Log\LoggerInterface;
	use Quellabs\Contracts\Context\MethodContextInterface;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
	/**
	 * Provides a contextual LoggerInterface implementation to the dependency
	 * injection container. Each consumer receives a Logger instance configured
	 * with the handler and channel specified via metadata, or sensible defaults.
	 *
	 * Logger instances are cached by their full configuration (channel, provider,
	 * logfile) so that repeated injections with the same settings return the same
	 * instance rather than constructing a new one each time.
	 *
	 * Supported $metadata keys:
	 *   'context' — handler identifier: 'stream' (default), 'rotating', 'stderr'
	 *   'logfile' — overrides the default log file path (stream and rotating only)
	 *   'channel' — Monolog channel label; defaults to 'app'
	 */
	class LoggerInterfaceProvider extends ServiceProvider {
		
		/** @var string Default log file */
		private string $logfile;
		
		/** @var array<string, LoggerInterface> Cached logger instances keyed by channel name */
		private array $loggers = [];
		
		/**
		 * LoggerInterfaceProvider constructor
		 * @param string $logfile
		 */
		public function __construct(string $logfile) {
			$this->logfile = $logfile;
		}
		
		/**
		 * Determines if this provider can handle the requested class.
		 * @param class-string $className The fully qualified class name being requested
		 * @param array<string, mixed> $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === LoggerInterface::class;
		}
		
		/**
		 * Creates and returns a Logger instance configured per the supplied metadata.
		 * @param class-string $className The class name being requested (should be LoggerInterface::class)
		 * @param array<int|string, mixed> $dependencies Dependencies for the class (unused)
		 * @param array<string, mixed> $metadata May contain 'provider', 'logfile', and 'channel' keys
		 * @param MethodContextInterface|null $methodContext Context about the class requesting the logger (unused)
		 * @return LoggerInterface The configured logger instance
		 */
		public function createInstance(
			string $className,
			array $dependencies,
			array $metadata,
			?MethodContextInterface $methodContext = null
		): LoggerInterface {
			// Resolve all configuration from metadata, falling back to defaults.
			// Use is_string guards — PHPStan at strict level rejects casts on mixed.
			$channel = is_string($metadata['channel'] ?? null) ? $metadata['channel'] : 'app';
			$provider = is_string($metadata['context'] ?? null) ? $metadata['context'] : 'stream';
			
			// Resolve logfile
			$logfile = is_string($metadata['logfile'] ?? null) ? $metadata['logfile'] : $this->logfile;
			
			if (!str_starts_with($logfile, DIRECTORY_SEPARATOR)) {
				$logfile = ComposerUtils::getProjectRoot() . '/storage/logs/' . $logfile;
			}
			
			// Cache key includes channel, provider, and logfile so that two injections
			// into the same class with different handlers or paths get distinct instances
			$cacheKey = $channel . '|' . $provider . '|' . $logfile;
			
			// Return the cached instance if one already exists for this combination
			if (isset($this->loggers[$cacheKey])) {
				return $this->loggers[$cacheKey];
			}
			
			// Instantiate the handler concretely so PHPStan can verify constructor signatures
			$handler = match ($provider) {
				'stream' => new StreamHandler($logfile, Level::Debug),
				'rotating' => new RotatingFileHandler($logfile, 0, Level::Debug),
				'stderr' => new ErrorLogHandler(),
				default => throw new \InvalidArgumentException(
					"Unsupported logger provider '{$provider}'. Supported values: stream, rotating, stderr."
				),
			};
			
			// Create the logger
			$logger = new Logger($channel);
			$logger->pushHandler($handler);
			return $this->loggers[$cacheKey] = $logger;
		}
	}