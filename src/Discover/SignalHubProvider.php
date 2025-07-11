<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\SignalHub\SignalHub;
	use Quellabs\SignalHub\SignalHubLocator;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
	/**
	 * Service provider for the Canvas framework kernel.
	 *
	 * This class is responsible for providing the framework SignalHub instance
	 * to the dependency injection container. It ensures that the same SignalHub
	 * instance is returned whenever the SignalHub class is requested.
	 */
	class SignalHubProvider extends ServiceProvider {
		
		/**
		 * Determines if this provider can handle the requested class
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === SignalHub::class;
		}
		
		/**
		 * Creates and returns the kernel instance
		 * @param string $className The class name being requested (should be Kernel::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @return SignalHub The signal hub instance
		 */
		public function createInstance(string $className, array $dependencies): SignalHub {
			return SignalHubLocator::getInstance();
		}
	}