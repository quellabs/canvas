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
		 * @var Container
		 */
		private static Container $container;
		
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
		}
		
		/**
		 * Check if the legacy bridge has been initialized
		 * @return bool True if initialized, false otherwise
		 */
		public static function isInitialized(): bool {
			return self::$initialized;
		}
		
		/**
		 * Get the container itself
		 * @return Container The dependency injection container
		 */
		public static function container(): Container {
			return self::$container;
		}
	}

	// Declared at file scope, not nested inside a method, so it is only ever
	// declared once (when this file is first included by the autoloader)
	// rather than once per LegacyBridge::initialize() call in the same process.
	// Without a leading "\", PHP registers it under the current namespace
	// (__NAMESPACE__ . '\canvas'), not the global namespace — the existence
	// check must match that.
	if (!function_exists(__NAMESPACE__ . '\\canvas')) {
		/**
		 * Global helper function for accessing the Canvas container from legacy code
		 * @param string|array<string, mixed>|null $context Optional DI context to scope resolution, as accepted by Container::for()
		 * @return Container The container, scoped to $context when given
		 */
		function canvas(string|array|null $context = null): Container {
			$container = LegacyBridge::container();
			return $context === null ? $container : $container->for($context);
		}
	}