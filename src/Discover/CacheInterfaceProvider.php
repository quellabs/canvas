<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\CacheKey;
	use Quellabs\Contracts\Context\MethodContext;
	use Quellabs\Discover\Discover;
	use Quellabs\Canvas\Cache\Foundation\FileCache;
	use Quellabs\Canvas\Cache\Contracts\CacheInterface;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
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
		const string DEFAULT_CACHE_KEY = "default";
		
		/**
		 * Singleton instance of the cache implementation
		 * @var CacheInterface[] $cache Holds the cached instance to ensure singleton behavior
		 */
		private array $cache = [];
		
		/** @var AnnotationReader AnnotationReader */
		private AnnotationReader $annotationReader;
		
		/**
		 * CacheInterfaceProvider constructor
		 * @param AnnotationReader $annotationReader
		 */
		public function __construct(AnnotationReader $annotationReader) {
			$this->annotationReader = $annotationReader;
		}
		
		/**
		 * Determines if this provider can handle the requested class.
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			// Only provide instances for the CacheInterface contract
			return $className === CacheInterface::class;
		}
		
		/**
		 * Creates and returns the cache interface instance.
		 * @param string $className The class name being requested (should be CacheInterface::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @param MethodContext|null $methodContext
		 * @return CacheInterface The cache interface implementation
		 * @throws AnnotationReaderException
		 */
		public function createInstance(string $className, array $dependencies, ?MethodContext $methodContext=null): CacheInterface {
			// Default cache key
			$cacheKey = self::DEFAULT_CACHE_KEY;
			
			// Read the annotations of the class/method
			if ($methodContext !== null) {
				$annotations = $this->annotationReader->getMethodAnnotations(
					$methodContext->getClassName(),
					$methodContext->getMethodName(),
					CacheKey::class
				);
				
				if (!$annotations->isEmpty()) {
					$cacheKey = $annotations[0]->getKey();
				}
			}
			
			// Create a new Discover instance to locate the project root
			$discover = new Discover();
			
			// Return existing instance if already created (singleton pattern)
			if (isset($this->cache[$cacheKey])) {
				return $this->cache[$cacheKey];
			}
			
			// Build the cache directory path: {project_root}/storage/cache/auto
			$cachePath = $discover->getProjectRoot() . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR . $cacheKey;
			
			// Create and store the FileCache instance, then return it
			return $this->cache[$cacheKey] = new FileCache($cachePath);
		}
	}