<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Contracts\Discovery\ProviderDefinition;
	use Quellabs\Contracts\Discovery\ProviderInterface;
	use Quellabs\DependencyInjection\Container;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Exceptions\ProviderInstantiationException;
	
	/**
	 * A DI-aware extension of Discover that resolves providers through the
	 * dependency injection container instead of instantiating them directly.
	 *
	 * The base Discover class uses bare `new $className()` instantiation, which
	 * breaks any provider that declares constructor dependencies. This subclass
	 * overrides that behaviour so providers can be autowired like any other
	 * container-managed service.
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
		 * Instantiate a provider through the DI container instead of directly.
		 * Preserves the base class config-loading behaviour so providers still
		 * receive their merged configuration after construction.
		 * @param ProviderDefinition $definition Provider definition
		 * @return ProviderInterface Successfully instantiated and configured provider
		 * @throws ProviderInstantiationException If the class is missing or configuration fails
		 */
		protected function instantiateProvider(ProviderDefinition $definition): ProviderInterface {
			// Fetch the class
			$className = $definition->className;
			
			// Verify the provider class exists before asking the container for it
			if (!class_exists($className)) {
				throw new ProviderInstantiationException(
					"Provider class '{$className}' does not exist",
					ProviderInstantiationException::CLASS_NOT_FOUND,
					$definition
				);
			}
			
			// Resolve through DI so constructor dependencies are autowired
			$provider = $this->di->get($className);
			
			try {
				// Preserve base class config behavior: load files, merge with defaults,
				// and apply the result to the provider
				$loadedConfig = $this->loadConfigFiles($definition->configFiles);
				$finalConfig = array_replace_recursive($definition->defaults, $loadedConfig);
				$provider->setConfig($finalConfig);
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