<?php
	
	namespace Quellabs\Canvas\Logger;
	
	use Monolog\Handler\AbstractHandler;
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
	 * injection container. Each consuming class receives a Logger instance
	 * pre-configured with its own class name as the channel, so log output
	 * is automatically namespaced without any manual configuration.
	 *
	 * Logger instances are cached by channel name so that repeated injections
	 * into the same class return the same instance rather than constructing a
	 * new one each time.
	 *
	 * Handler resolution order:
	 *   1. $metadata['provider'] — a string identifier mapped via HANDLERS
	 *   2. Default — StreamHandler writing to storage/logs/canvas.log
	 *
	 * Supported $metadata['provider'] values:
	 *   'stream'   — StreamHandler writing to storage/logs/canvas.log (default)
	 *   'stderr'   — ErrorLogHandler writing to PHP's error log
	 *   'rotating' — RotatingFileHandler with daily rotation in storage/logs/
	 */
	class LoggerInterfaceProvider extends ServiceProvider {
		
		/** @var string Default log file */
		private string $logfile;
		
		/** @var array<string, class-string<AbstractHandler>> Maps provider identifiers to handler class names */
		private const array HANDLERS = [
			'stream'   => StreamHandler::class,
			'stderr'   => ErrorLogHandler::class,
			'rotating' => RotatingFileHandler::class,
		];
		
		/** @var array<string> Handler identifiers that require a file path as their first constructor argument */
		private const array HANDLERS_REQUIRE_PATH = ['stream', 'rotating'];
		
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
		 * Creates and returns a Logger instance for the consuming class.
		 * The channel is derived from the consuming class name, giving each
		 * class its own named logger without any manual setup.
		 * @param class-string $className The class name being requested (should be LoggerInterface::class)
		 * @param array<int|string, mixed> $dependencies Dependencies for the class (unused)
		 * @param array<string, mixed> $metadata Metadata as passed by the container — may contain 'provider' key with a handler identifier string, and 'logfile' key to override the default log path
		 * @param MethodContextInterface|null $methodContext Context about the class requesting the logger
		 * @return LoggerInterface The configured logger instance
		 */
		public function createInstance(
			string $className,
			array $dependencies,
			array $metadata,
			?MethodContextInterface $methodContext = null
		): LoggerInterface {
			// Derive the channel from the consuming class name.
			// Fall back to 'app' when called outside a request context.
			$channel = $methodContext?->getClassName() ?? 'app';
			
			// Use the short class name as the channel to keep log output readable
			$channel = substr($channel, strrpos($channel, '\\') + 1);
			
			// Return the cached instance if one already exists for this channel
			if (isset($this->loggers[$channel])) {
				return $this->loggers[$channel];
			}
			
			// Resolve the handler from the provider identifier, or use the default if none specified
			if (isset($metadata['provider'])) {
				if (!isset(self::HANDLERS[$metadata['provider']])) {
					$supported = implode(', ', array_keys(self::HANDLERS));
					
					throw new \InvalidArgumentException(
						"Unsupported logger provider '{$metadata['provider']}'. Supported values: {$supported}."
					);
				}
				
				$handlerClass = self::HANDLERS[$metadata['provider']];
				$logfile = $metadata['logfile'] ?? $this->logfile;

				if (in_array($metadata['provider'], self::HANDLERS_REQUIRE_PATH)) {
					$handler = new $handlerClass($logfile);
				} else {
					$handler = new $handlerClass();
				}
			} else {
				$handler = $this->createDefaultHandler();
			}
			
			// Create the logger
			$logger = new Logger($channel);
			$logger->pushHandler($handler);
			return $this->loggers[$channel] = $logger;
		}
		
		/**
		 * Creates the default log handler.
		 * Writes to storage/logs/canvas.log at DEBUG level.
		 * @return AbstractHandler
		 */
		private function createDefaultHandler(): AbstractHandler {
			return new StreamHandler($this->logfile, Level::Debug);
		}
	}