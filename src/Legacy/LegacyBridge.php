<?php
	
	namespace Quellabs\Canvas\Legacy;
	
	use Quellabs\DependencyInjection\Container;
	
	/**
	 * LegacyBridge provides a static interface to access Canvas services from legacy code
	 *
	 * This class acts as a bridge between new dependency injection container system
	 * and legacy code that cannot use constructor injection. It maintains a static
	 * reference to the container and provides global access to services.
	 */
	class LegacyBridge {

		/**
		 * Static reference to the dependency injection container
		 * @var Container|null
		 */
		private static ?Container $container = null;
		
		/**
		 * Flag to track whether the bridge has been initialized
		 * @var bool
		 */
		private static bool $initialized = false;
		
		/**
		 * Initialize the legacy bridge with a container instance
		 * This method must be called once during application bootstrap
		 * to make services available to legacy code.
		 * @param Container $container The dependency injection container
		 * @return void
		 */
		public static function initialize(Container $container): void {
			// Store the container reference
			self::$container = $container;
			self::$initialized = true;
			
			// Register a few essential global functions
			self::registerGlobalFunctions();
		}
		
		/**
		 * Check if the legacy bridge has been initialized
		 * @return bool True if initialized, false otherwise
		 */
		public static function isInitialized(): bool {
			return self::$initialized;
		}
		
		/**
		 * Get any service from the Canvas container
		 * @param string $service The service identifier/name to retrieve
		 * @return mixed The requested service instance
		 * @throws \RuntimeException If the bridge hasn't been initialized
		 */
		public static function get(string $service): mixed {
			// Ensure the bridge has been initialized before attempting to access services
			if (!self::$container) {
				throw new \RuntimeException('LegacyBridge not initialized.');
			}
			
			// Delegate to the container's get method
			return self::$container->get($service);
		}
		
		/**
		 * Get the container itself
		 * @return Container The dependency injection container
		 */
		public static function container(): Container {
			return self::$container;
		}
		
		/**
		 * Register a few essential global functions for legacy code
		 * @return void
		 */
		private static function registerGlobalFunctions(): void {
			// Only register the function if it doesn't already exist to avoid conflicts
			if (!function_exists('canvas')) {
				/**
				 * Global helper function for accessing Canvas services
				 * @param string|null $service Optional service name to retrieve
				 * @return mixed If $service provided, returns the service; otherwise returns the container
				 */
				function canvas(string $service = null): mixed {
					// If a service name is provided, get that specific service
					// Otherwise, return the container itself for advanced usage
					return $service ? LegacyBridge::get($service) : LegacyBridge::container();
				}
			}
		}
	}