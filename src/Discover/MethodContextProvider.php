<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
	/**
	 * Service provider for the Routing Method Context
	 */
	class MethodContextProvider extends ServiceProvider {
		
		/**
		 * The method context instance to be provided
		 * @var MethodContextInterface
		 */
		private MethodContextInterface $context;
		
		/**
		 * Constructor - initializes the provider with a MethodContext instance
		 * @param MethodContextInterface $context
		 */
		public function __construct(MethodContextInterface $context) {
			$this->context = $context;
		}
		
		/**
		 * Determines if this provider can handle the requested class
		 * @param string $className The fully qualified class name being requested
		 * @param array<string, mixed> $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			return $className === MethodContextInterface::class;
		}
		
		/**
		 * Creates and returns the method context instance
		 * @param string $className The class name being requested (should be \Quellabs\Canvas\Routing\MethodContext::class)
		 * @param array<int, mixed> $dependencies Dependencies for the class (unused since we return existing instance)
		 * @param array<string, mixed> $metadata Metadata as passed by Discover
		 * @param MethodContextInterface|null $methodContext
		 * @return MethodContextInterface The method context instance
		 */
		public function createInstance(string $className, array $dependencies, array $metadata, ?\Quellabs\Contracts\Context\MethodContextInterface $methodContext=null): object {
			return $this->context;
		}
	}