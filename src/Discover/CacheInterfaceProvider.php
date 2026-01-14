<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\CacheContext;
	use Quellabs\Contracts\Context\MethodContext;
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Cache\FileCache;
	use Quellabs\Contracts\Cache\CacheInterface;
	use Quellabs\Contracts\DependencyInjection\Container;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	use Quellabs\Support\ComposerUtils;
	
	/**
	 * This class is responsible for providing a CacheInterface implementation
	 * to the dependency injection container. It uses the singleton pattern to
	 * ensure that the same cache instance is returned whenever the CacheInterface
	 * is requested, preventing multiple cache instances from being created.
	 */
	class CacheInterfaceProvider extends ServiceProvider {
		
		/**
		 * The default cache namespace
		 */
		private const string DEFAULT_NAMESPACE = "default";
		
		/**
		 * Singleton instances of cache implementations
		 * @var CacheInterface[] $cache Holds the cached instances to ensure singleton behavior
		 */
		private array $cache = [];
		
		/** @var AnnotationReader Used to read method annotations */
		private AnnotationReader $annotationReader;
		
		/** @var Container Used for dependency injection */
		private Container $dependencyInjector;
		
		/** @var array Cache configuration loaded from config file */
		private array $cacheConfig;
		
		/**
		 * CacheInterfaceProvider constructor
		 * @param Container $dependencyInjector
		 * @param AnnotationReader $annotationReader
		 */
		public function __construct(
			Container $dependencyInjector,
			AnnotationReader $annotationReader
		) {
			$this->dependencyInjector = $dependencyInjector;
			$this->annotationReader = $annotationReader;
			$this->cacheConfig = $this->loadCacheConfig();
		}
		
		/**
		 * Determines if this provider can handle the requested class.
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === CacheInterface::class;
		}
		
		/**
		 * Creates and returns the cache interface instance.
		 * @param string $className The class name being requested (should be CacheInterface::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @param array $metadata Metadata as passed by Discover - may contain 'provider' key
		 * @param MethodContext|null $methodContext Context about the method requesting the cache
		 * @return CacheInterface The cache interface implementation
		 * @throws AnnotationReaderException
		 */
		public function createInstance(
			string $className,
			array $dependencies,
			array $metadata,
			?MethodContext $methodContext = null
		): CacheInterface {
			// Resolve the cache context from method annotations
			$context = $this->resolveContext($methodContext, $dependencies);
			
			// Determine which cache provider to use based on metadata or annotations
			$providerName = $metadata['provider'] ?? $context['driver'] ?? null;
			$providerClass = $this->getProviderClass($providerName);
			
			// Create a unique cache key for this provider and context combination
			$cacheKey = $providerClass . ':' . $context['hash'];
			
			// Return existing instance if already created (singleton pattern)
			if (isset($this->cache[$cacheKey])) {
				return $this->cache[$cacheKey];
			}

			// Gather parameters from all sources: MethodContext, InterceptWith and config/cache.php
			$userConfig = $dependencies['config'] ?? [];
			
			$totalConfig = array_merge(
				$this->getConnectionConfig($providerName),
				$context['params'],
				$userConfig
			);
			
			// Prepare constructor parameters for the cache implementation
			$constructorParams = [
				'namespace' => $context['namespace'],
				'config'    => $totalConfig,
				...$context['params']
			];

			// Create and store new cache instance
			$instance = $this->dependencyInjector->make($providerClass, $constructorParams);

			// Ensure the instance implements CacheInterface
			if (!$instance instanceof CacheInterface) {
				throw new \RuntimeException(
					"Cache provider {$providerClass} must implement CacheInterface"
				);
			}
			
			// Return the instance
			return $this->cache[$cacheKey] = $instance;
		}
		
		/**
		 * Resolves cache context from method annotations.
		 * @param MethodContext|null $methodContext The method context to analyze
		 * @return array Contains namespace, params, and hash for caching
		 * @throws AnnotationReaderException
		 */
		private function resolveContext(?MethodContext $methodContext, array $dependencies): array {
			$params = $dependencies;
			$namespace = self::DEFAULT_NAMESPACE;
			
			// Check if namespace is passed in the dependencies
			if (!empty($dependencies['namespace'])) {
				$namespace = $dependencies['namespace'];
			}
			
			// Check if we have method context to read annotations from
			if ($methodContext !== null) {
				// Read CacheContext annotations from the method
				$annotations = $this->annotationReader->getMethodAnnotations(
					$methodContext->getClassName(),
					$methodContext->getMethodName(),
					CacheContext::class
				);
				
				// Extract parameters from the first annotation if it exists
				if (!$annotations->isEmpty()) {
					$params = $annotations[0]->getParameters();
					$namespace = $params['namespace'] ?? $namespace;
				}
			}
			
			return [
				'namespace' => $namespace,
				'params'    => $params,
				'driver'    => $params['driver'] ?? null,
				'hash'      => $namespace . ':' . md5(serialize($params))
			];
		}
		
		/**
		 * Loads cache configuration from the config file.
		 * @return array The cache configuration array
		 * @throws \RuntimeException If the configuration file exists but cannot be loaded
		 */
		private function loadCacheConfig(): array {
			$projectRoot = ComposerUtils::getProjectRoot();
			$configPath = $projectRoot . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'cache.php';
			
			// Return empty config if the file doesn't exist or isn't readable
			if (!is_readable($configPath)) {
				return [];
			}
			
			try {
				// Include the PHP configuration file and return its contents
				return include $configPath;
			} catch (\Throwable $e) {
				// Wrap any exception in a more specific RuntimeException
				throw new \RuntimeException("Failed to load cache configuration: " . $e->getMessage(), 0, $e);
			}
		}
		
		/**
		 * Resolves and returns the cache provider class name based on configuration.
		 * @param string|null $provider Specific provider name to use, or null for default
		 * @return string The fully qualified class name of the cache provider
		 * @throws \InvalidArgumentException When specified provider is not configured
		 */
		private function getProviderClass(?string $provider): string {
			// Fetch the list of drivers
			$drivers = $this->cacheConfig['drivers'] ?? [];
			
			// Use specific provider if requested, otherwise fall back to default
			$targetProvider = $provider ?? $this->cacheConfig['default'] ?? null;
			
			// Return the provider class if it exists in drivers
			if ($targetProvider && isset($drivers[$targetProvider]['class'])) {
				return $drivers[$targetProvider]['class'];
			}
			
			// Throw error if a specific provider was requested but not found
			if ($targetProvider) {
				$available = implode(', ', array_keys($drivers));
				$type = $provider ? 'Cache provider' : 'Default cache provider';
				
				throw new \InvalidArgumentException(
					"{$type} '{$targetProvider}' not found. Available providers: {$available}"
				);
			}
			
			// Final fallback when no configuration exists
			return FileCache::class;
		}
		
		/**
		 * Gets connection configuration for a specific cache provider.
		 * @param string|null $providerName The provider name (e.g., 'redis', 'memcached')
		 * @return array Connection configuration array (empty if not found)
		 */
		private function getConnectionConfig(?string $providerName): array {
			// If no provider name, try to get config for the default provider
			if ($providerName === null) {
				$providerName = $this->cacheConfig['default'] ?? null;
			}
			
			// Get connection configuration from the connections section
			$connections = $this->cacheConfig['drivers'] ?? [];
			
			// Return the connection
			return $connections[$providerName] ?? [];
		}
	}