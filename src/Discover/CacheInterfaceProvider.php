<?php
	
	namespace Quellabs\Canvas\Discover;
	
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
		 * Singleton instance of the cache implementation
		 * @var CacheInterface|null $cache Holds the cached instance to ensure singleton behavior
		 */
		private ?CacheInterface $cache = null;
		
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
		 * @return CacheInterface The cache interface implementation
		 */
		public function createInstance(string $className, array $dependencies): CacheInterface {
			// Return existing instance if already created (singleton pattern)
			if (!is_null($this->cache)) {
				return $this->cache;
			}
			
			// Create a new Discover instance to locate the project root
			$discover = new Discover();
			
			// Build the cache directory path: {project_root}/storage/cache/auto
			$cachePath = $discover->getProjectRoot() . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR . 'auto';
			
			// Create and store the FileCache instance, then return it
			return $this->cache = new FileCache($cachePath);
		}
	}