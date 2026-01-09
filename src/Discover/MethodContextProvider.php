<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Quellabs\Contracts\Context\MethodContext;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
	/**
	 * Service provider for the Routing Method Context
	 */
	class MethodContextProvider extends ServiceProvider {
		
		/**
		 * The method context instance to be provided
		 * @var \Quellabs\Canvas\Routing\Context\MethodContext
		 */
		private \Quellabs\Canvas\Routing\Context\MethodContext $context;
		
		/**
		 * Constructor - initializes the provider with a MethodContext instance
		 * @param \Quellabs\Canvas\Routing\Context\MethodContext $context
		 */
		public function __construct(MethodContext $context) {
			$this->context = $context;
		}
		
		/**
		 * Determines if this provider can handle the requested class
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return
				$className === MethodContextInterface::class ||
				$className === MethodContext::class;
		}
		
		/**
		 * Creates and returns the method context instance
		 * @param string $className The class name being requested (should be \Quellabs\Canvas\Routing\MethodContext::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @param array $metadata Metadata as passed by Discover
		 * @param MethodContext|null $methodContext
		 * @return MethodContext The method context instance
		 */
		public function createInstance(string $className, array $dependencies, array $metadata, ?MethodContext $methodContext=null): object {
			return $this->context;
		}
	}