<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	use Quellabs\Discover\Discover;
	
	/**
	 * Service provider for the Canvas framework kernel.
	 *
	 * This class is responsible for providing the framework kernel instance
	 * to the dependency injection container. It ensures that the same kernel
	 * instance is returned whenever the Kernel class is requested.
	 */
	class DiscoverProvider extends ServiceProvider {
		
		/**
		 * The framework Discover instance to be provided
		 * @var Discover
		 */
		private Discover $discover;
		
		/**
		 * Constructor - initializes the provider with a Discover instance
		 * @param Discover $discover
		 */
		public function __construct(Discover $discover) {
			$this->discover = $discover;
		}
		
		/**
		 * Determines if this provider can handle the requested class
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === Discover::class;
		}
		
		/**
		 * Creates and returns the kernel instance
		 * @param string $className The class name being requested (should be Kernel::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @return Discover The framework kernel instance
		 */
		public function createInstance(string $className, array $dependencies): Discover {
			return $this->discover;
		}
	}