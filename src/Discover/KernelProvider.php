<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Canvas\Kernel;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
	/**
	 * Service provider for the Canvas framework kernel.
	 *
	 * This class is responsible for providing the framework kernel instance
	 * to the dependency injection container. It ensures that the same kernel
	 * instance is returned whenever the Kernel class is requested.
	 */
	class KernelProvider extends ServiceProvider {
		
		/**
		 * The framework kernel instance to be provided
		 * @var Kernel
		 */
		private Kernel $framework;
		
		/**
		 * Constructor - initializes the provider with a kernel instance
		 * @param Kernel $framework The framework kernel instance to provide
		 */
		public function __construct(Kernel $framework) {
			$this->framework = $framework;
		}
		
		/**
		 * Determines if this provider can handle the requested class
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === Kernel::class;
		}
		
		/**
		 * Creates and returns the kernel instance
		 * @param string $className The class name being requested (should be Kernel::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @return Kernel The framework kernel instance
		 */
		public function createInstance(string $className, array $dependencies): Kernel {
			return $this->framework;
		}
	}