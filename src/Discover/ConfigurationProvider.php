<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Canvas\Configuration\Configuration;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
	/**
	 * Service provider for the Canvas framework Configuration class.
	 *
	 * This class is responsible for providing the framework configuration instance
	 * to the dependency injection container. It ensures that the same configuration
	 * instance is returned whenever the Configuration class is requested.
	 */
	class ConfigurationProvider extends ServiceProvider {
		
		/**
		 * The instance to be provided
		 * @var Configuration
		 */
		private Configuration $configuration;
		
		/**
		 * Constructor - initializes the provider with a Configuration instance
		 * @param Configuration $framework The instance to provide
		 */
		public function __construct(Configuration $framework) {
			$this->configuration = $framework;
		}
		
		/**
		 * Determines if this provider can handle the requested class
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === Configuration::class;
		}
		
		/**
		 * Creates and returns the Configuration instance
		 * @param string $className The class name being requested (should be Configuration::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @return Configuration The returned instance
		 */
		public function createInstance(string $className, array $dependencies): Configuration {
			return $this->configuration;
		}
	}