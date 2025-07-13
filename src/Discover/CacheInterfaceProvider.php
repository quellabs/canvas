<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Discover\Discover;
	use Quellabs\Canvas\Annotations\CacheNamespace;
	use Quellabs\Contracts\Context\MethodContext;
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Canvas\Cache\Foundation\FileCache;
	use Quellabs\Canvas\Cache\Contracts\CacheInterface;
	use Quellabs\Contracts\DependencyInjection\Container;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	
	/**
	 * This class is responsible for providing a CacheInterface implementation
	 * to the dependency injection container. It uses the singleton pattern to
	 * ensure that the same cache instance is returned whenever the CacheInterface
	 * is requested, preventing multiple cache instances from being created.
	 */
	class CacheInterfaceProvider extends ServiceProvider {
		
		/**
		 * The default cache key
		 */
		const string DEFAULT_NAMESPACE = "default";
		
		/**
		 * Singleton instance of the cache implementation
		 * @var CacheInterface[] $cache Holds the cached instance to ensure singleton behavior
		 */
		private array $cache = [];
		
		/** @var AnnotationReader AnnotationReader */
		private AnnotationReader $annotationReader;
		
		/** @var Container Used for dependency injection */
		private Container $dependencyInjector;
		
		/** @var Discover Discovery component for fetching the project root */
		private Discover $discover;
		
		/** @var string|null Project root folder */
		private ?string $projectRoot;
		
		/** @var string Path to cache.php */
		private string $pathToConfig;
		
		/** @var array Cache configuration */
		private array $cacheConfig;
		
		/**
		 * CacheInterfaceProvider constructor
		 * @param Discover $discover
		 * @param Container $dependencyInjector
		 * @param AnnotationReader $annotationReader
		 */
		public function __construct(
			Discover $discover,
			Container $dependencyInjector,
			AnnotationReader $annotationReader
		) {
			$this->dependencyInjector = $dependencyInjector;
			$this->discover = $discover;
			$this->annotationReader = $annotationReader;
			$this->projectRoot = $this->discover->getProjectRoot();
			$this->pathToConfig = $this->projectRoot . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "cache.php";
			$this->cacheConfig = $this->getCacheConfig();
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
		 * @param array $metadata Metadata as passed by Discover
		 * @param MethodContext|null $methodContext
		 * @return CacheInterface The cache interface implementation
		 * @throws AnnotationReaderException
		 */
		public function createInstance(string $className, array $dependencies, array $metadata, ?MethodContext $methodContext=null): CacheInterface {
			// Default cache key
			$namespace = self::DEFAULT_NAMESPACE;
			
			// Read the annotations of the class/method
			if ($methodContext !== null) {
				$annotations = $this->annotationReader->getMethodAnnotations(
					$methodContext->getClassName(),
					$methodContext->getMethodName(),
					CacheNamespace::class
				);
				
				if (!$annotations->isEmpty()) {
					$namespace = $annotations[0]->getNamespace();
				}
			}
			
			// Check which kind of cache we want to create
			$providerClass = $this->getProviderClass($metadata['provider'] ?? null);
			
			// Return existing instance if already created (singleton pattern)
			if (isset($this->cache["{$providerClass}:{$namespace}"])) {
				return $this->cache["{$providerClass}:{$namespace}"];
			}
			
			// Create and store the FileCache instance, then return it
			return $this->cache["{$providerClass}:{$namespace}"] = $this->dependencyInjector->make($providerClass, [
				'namespace' => $namespace,
			]);
		}
		
		/**
		 * Fetches the configuration
		 * @return array
		 * @throws \RuntimeException
		 */
		private function getCacheConfig(): array {
			// Check if the configuration file exists at the specified path
			if (!file_exists($this->pathToConfig)) {
				return [];
			}
			
			// Verify that the configuration file is readable
			if (!is_readable($this->pathToConfig)) {
				return [];
			}
			
			try {
				// Include the PHP configuration file and return its contents
				// This assumes the config file returns an array
				return include $this->pathToConfig;
			} catch (\Throwable $e) {
				// Wrap any exception in a more specific RuntimeException
				// This provides better error context for debugging
				throw new \RuntimeException("Failed to load cache configuration: " . $e->getMessage());
			}
		}
		
		/**
		 * Resolves and returns the cache provider class name based on configuration
		 * @param string|null $provider Specific provider name to use, or null for default
		 * @return string The fully qualified class name of the cache provider
		 * @throws \InvalidArgumentException When specified provider is not configured
		 */
		private function getProviderClass(?string $provider): string {
			// Fetch the list of configured cache drivers from config
			$drivers = $this->cacheConfig['drivers'] ?? [];
			
			// If a specific provider was requested, try to find it
			if ($provider !== null) {
				// Return the provider class if found, otherwise throw descriptive error
				return $drivers[$provider] ?? throw new \InvalidArgumentException(
					"Cache provider '{$provider}' is not configured. Available: " . implode(', ', array_keys($drivers))
				);
			}
			
			// No specific provider requested, so use the configured default
			$default = $this->cacheConfig['default'] ?? null;
			
			// If default is set, validate it exists in drivers
			if ($default !== null) {
				if (!isset($drivers[$default])) {
					throw new \InvalidArgumentException(
						"Default cache provider '{$default}' is not configured. Available: " . implode(', ', array_keys($drivers))
					);
				}
				
				return $drivers[$default];
			}
			
			// Final fallback: use FileCache when no default is configured
			return FileCache::class;
		}
	}