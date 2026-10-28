<?php
	
	namespace Quellabs\Canvas\Logger;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Canvas\Annotations\LoggerContext;
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
	 * via @WithContext (handler selection) and @LoggerContext (logfile/channel
	 * overrides), or sensible defaults.
	 *
	 * Logger instances are cached by their full configuration (channel, provider,
	 * logfile) so that repeated injections with the same settings return the same
	 * instance rather than constructing a new one each time.
	 *
	 * @WithContext's literal context tag ('stream' default, 'rotating', 'stderr')
	 * is the sole handler selector. @LoggerContext, read directly off the method,
	 * only supplies 'logfile'/'channel' overrides — it has no say over the handler.
	 * A method may carry several @LoggerContext instances, each tagged with the
	 * context it configures (`@LoggerContext(context: "rotating", logfile: "...")`),
	 * plus an optional untagged one used when none of the tagged ones match.
	 */
	class LoggerInterfaceProvider extends ServiceProvider {
		
		/** @var string Default log file */
		private string $logfile;
		
		/** @var AnnotationReader Used to read @LoggerContext from the requesting method */
		private AnnotationReader $annotationReader;
		
		/** @var array<string, LoggerInterface> Cached logger instances keyed by channel name */
		private array $loggers = [];
		
		/**
		 * LoggerInterfaceProvider constructor
		 * @param string $logfile
		 * @param AnnotationReader $annotationReader
		 */
		public function __construct(string $logfile, AnnotationReader $annotationReader) {
			$this->logfile = $logfile;
			$this->annotationReader = $annotationReader;
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
		 * Creates and returns a Logger instance configured per @WithContext's literal
		 * tag (handler selection) and @LoggerContext (logfile/channel overrides).
		 * @param class-string $className The class name being requested (should be LoggerInterface::class)
		 * @param array<int|string, mixed> $dependencies Dependencies for the class (unused)
		 * @param array<string, mixed> $metadata May contain a 'context' key naming the handler
		 * @param MethodContextInterface|null $methodContext Context about the class requesting the logger
		 * @return LoggerInterface The configured logger instance
		 */
		public function createInstance(
			string $className,
			array $dependencies,
			array $metadata,
			?MethodContextInterface $methodContext = null
		): LoggerInterface {
			// @WithContext's literal context tag is the sole handler selector
			$provider = is_string($metadata['context'] ?? null) ? $metadata['context'] : 'stream';
			
			// Pick the @LoggerContext instance that matches the resolved handler,
			// falling back to the untagged default (if any), falling back to [].
			$loggerContext = $this->resolveLoggerContext($methodContext, $provider);
			
			// Resolve all configuration, falling back to defaults.
			// Use is_string guards — PHPStan at strict level rejects casts on mixed.
			$channel = is_string($loggerContext['channel'] ?? null) ? $loggerContext['channel'] : 'app';
			
			// Resolve logfile
			$logfile = is_string($loggerContext['logfile'] ?? null) ? $loggerContext['logfile'] : $this->logfile;
			
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
		
		/**
		 * Reads @LoggerContext parameters off the requesting method, if present.
		 * A method may carry several @LoggerContext instances, one per resolved
		 * context; the one whose `context` matches $resolvedContext wins, falling
		 * back to the untagged instance (`context` omitted), if any.
		 * @param MethodContextInterface|null $methodContext Context about the class requesting the logger
		 * @param string $resolvedContext The handler tag resolved from @WithContext (or the 'stream' default)
		 * @return array<string, mixed> The matching annotation's parameters, or an empty array if none match
		 */
		private function resolveLoggerContext(?MethodContextInterface $methodContext, string $resolvedContext): array {
			if ($methodContext === null) {
				return [];
			}
			
			$className = $methodContext->getClassName();
			
			if (!class_exists($className)) {
				return [];
			}
			
			try {
				$annotations = $this->annotationReader->getMethodAnnotations(
					$className,
					$methodContext->getMethodName(),
					LoggerContext::class
				);
			} catch (\Throwable) {
				// Annotation parsing failed or no docblock present — proceed without overrides
				return [];
			}
			
			$default = null;
			
			foreach ($annotations as $annotation) {
				if (!$annotation instanceof LoggerContext) {
					continue;
				}
				
				if ($annotation->getContext() === $resolvedContext) {
					return $annotation->getParameters();
				}
				
				if ($annotation->getContext() === null) {
					$default = $annotation;
				}
			}
			
			return $default?->getParameters() ?? [];
		}
	}