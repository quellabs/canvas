<?php
	
	namespace Quellabs\Canvas\Discover;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Contracts\Context\MethodContext;
	use Quellabs\DependencyInjection\Provider\ServiceProvider;
	
	/**
	 * This class is responsible for providing an AnnotationReader implementation
	 * to the dependency injection container. It uses the singleton pattern.
	 */
	class AnnotationsReaderProvider extends ServiceProvider {
		
		/**
		 * @var AnnotationReader $annotationReader Holds the cached instance to ensure singleton behavior */
		private AnnotationReader $annotationReader;
		
		/**
		 * AnnotationsReaderProvider constructor
		 * @param AnnotationReader $annotationReader
		 */
		public function __construct(AnnotationReader $annotationReader) {
			$this->annotationReader = $annotationReader;
		}
		
		/**
		 * Determines if this provider can handle the requested class.
		 * @param string $className The fully qualified class name being requested
		 * @param array $metadata Additional metadata (unused in this implementation)
		 * @return bool True if this provider supports the requested class, false otherwise
		 */
		public function supports(string $className, array $metadata = []): bool {
			// Only provide instances for the CacheInterface contract
			return $className === AnnotationReader::class;
		}
		
		/**
		 * Creates and returns the cache interface instance.
		 * @param string $className The class name being requested (should be AnnotationReader::class)
		 * @param array $dependencies Dependencies for the class (unused since we return existing instance)
		 * @param MethodContext|null $methodContext
		 * @return AnnotationReader The cache interface implementation
		 */
		public function createInstance(string $className, array $dependencies, ?MethodContext $methodContext=null): AnnotationReader {
			return $this->annotationReader;
		}
	}