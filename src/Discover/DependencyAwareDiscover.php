<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Contracts\Discovery\ProviderDefinition;
	use Quellabs\Contracts\Discovery\ProviderInterface;
	use Quellabs\DependencyInjection\Container;
	use Quellabs\DependencyInjection\Provider\SimpleBinding;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Exceptions\ProviderInstantiationException;
	
	/**
	 * A DI-aware extension of Discover that resolves providers through the
	 * dependency injection container instead of instantiating them directly.
	 *
	 * The base Discover class uses bare `new $className()` instantiation, which
	 * breaks any provider that declares constructor dependencies. This subclass
	 * overrides only instantiateProvider() so providers are autowired via
	 * Container::instantiate() — which resolves constructor dependencies through
	 * the container without pushing the provider class onto the resolution stack,
	 * avoiding false circular dependency detection.
	 */
	class DependencyAwareDiscover extends Discover {
		
		/** @var Container Dependency injection container used to resolve providers */
		private Container $di;
		
		/**
		 * DependencyAwareDiscover constructor
		 * @param Container $di
		 */
		public function __construct(Container $di) {
			$this->di = $di;
		}
		
		/**
		 * Instantiate a provider with autowired constructor dependencies.
		 *
		 * Uses Container::instantiate() rather than get() or make() to avoid
		 * pushing the provider class onto the resolution stack — which would
		 * trigger false circular dependency errors when the container resolves
		 * the provider's dependencies during boot.
		 *
		 * The instantiated provider is registered as a SimpleBinding so that
		 * subsequent get() calls return the same singleton instance.
		 *
		 * @param ProviderDefinition $definition Provider definition
		 * @return ProviderInterface Successfully instantiated and configured provider
		 * @throws ProviderInstantiationException If the class is missing or configuration fails
		 * @throws \ReflectionException
		 */
		protected function instantiateProvider(ProviderDefinition $definition): ProviderInterface {
			$className = $definition->className;
			
			// Verify the provider class exists before attempting instantiation
			if (!class_exists($className)) {
				throw new ProviderInstantiationException(
					"Provider class '{$className}' does not exist",
					ProviderInstantiationException::CLASS_NOT_FOUND,
					$definition
				);
			}
			
			// Instantiate with autowired dependencies, bypassing the resolution stack
			$provider = $this->di->instantiate($className);
			
			// Validate that the result implements ProviderInterface
			if (!$provider instanceof ProviderInterface) {
				throw new ProviderInstantiationException(
					"Container did not return a valid provider for '{$className}'",
					ProviderInstantiationException::INSTANTIATION_FAILED,
					$definition
				);
			}
			
			// Register as a singleton so future get() calls return this instance
			// rather than triggering a fresh instantiation through the default provider
			$this->di->register(new SimpleBinding($className, $provider));
			
			try {
				// Load and apply configuration, matching base class behavior
				$loadedConfig = $this->loadConfigFiles($definition->configFiles);
				$provider->setConfig($loadedConfig);
			} catch (\Throwable $e) {
				throw new ProviderInstantiationException(
					"Failed to configure provider '{$className}': {$e->getMessage()}",
					ProviderInstantiationException::CONFIGURATION_FAILED,
					$definition,
					$e
				);
			}
			
			return $provider;
		}
	}