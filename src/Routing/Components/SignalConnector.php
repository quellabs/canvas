<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\ListenTo;
	use Quellabs\Canvas\Discover\DependencyAwareDiscover;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Contracts\SignalProviderInterface;
	use Quellabs\DependencyInjection\Container;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Scanner\ComposerScanner;
	use Quellabs\Discover\Scanner\DirectoryScanner;
	use Quellabs\SignalHub\Signal;
	use Quellabs\Support\ComposerUtils;
	use ReflectionClass;
	use ReflectionException;
	
	/**
	 * Wires signals to their slots using @ListenTo annotations on signal providers.
	 *
	 * Signal providers are discovered via Composer's extra.signal-hub.providers key.
	 * Each provider method annotated with @ListenTo("signal.name") is automatically
	 * connected to the matching signal — no manual connect() implementation needed.
	 *
	 * Both discovery and annotation scanning run once at construction time,
	 * since this class is container-managed (singleton lifecycle).
	 */
	class SignalConnector {
		
		/**
		 * @var AnnotationReader Used to read @ListenTo annotations from provider methods
		 */
		private AnnotationReader $annotationReader;
		
		/**
		 * @var Container Dependency Injector
		 */
		private Container $di;
		
		/**
		 * @var array<string, array<array{callable: callable, priority: int}>>
		 *      Maps signal names to the list of listeners that should be connected to them.
		 *      Built once at construction time from @ListenTo annotations.
		 */
		private array $listenerMap;
		
		/**
		 * Discovers signal providers and pre-builds the listener map from @ListenTo annotations.
		 * @param Kernel $kernel
		 */
		public function __construct(Kernel $kernel) {
			// Store annotation reader
			$this->annotationReader = $kernel->getAnnotationsReader();
			$this->di = $kernel->getDependencyInjector();
			
			// Default path for providers
			$defaultPath = ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "SignalProviders";
			$signalProviderPath = $kernel->getConfiguration()->get("signal_providers_path", $defaultPath);
			
			// Discover all packages that register themselves under the "signal-hub" family
			// If a SignalProviders directory exists, also scan that one.
			$discover = new DependencyAwareDiscover($this->di);
			$discover->addScanner(new ComposerScanner("signal-hub"));
			
			if (is_dir($signalProviderPath)) {
				$discover->addScanner(new DirectoryScanner([$signalProviderPath]));
			}
			
			$discover->discover();
			
			// Scan annotations once and cache the result — connect() is a hot path
			$this->listenerMap = $this->buildListenerMap($discover);
		}
		
		/**
		 * Wire a set of signals to their slots using the pre-built listener map.
		 * Each signal is matched by name; unmatched signals are silently skipped.
		 * @param Signal[] $signals Signals to wire, typically freshly discovered on a controller
		 * @return void
		 */
		public function connect(array $signals): void {
			foreach ($signals as $signal) {
				$listeners = $this->listenerMap[$signal->getName()] ?? [];
				
				foreach ($listeners as $listener) {
					$instance = $this->di->get($listener['className']);
					$signal->connect([$instance, $listener['method']], $listener['priority']);
				}
			}
		}
		
		/**
		 * Scans all discovered providers for @ListenTo annotations and builds a
		 * signal-name-keyed map of callables and their priorities.
		 * @return array<string, array<array{callable: callable, priority: int}>>
		 */
		private function buildListenerMap(Discover $discover): array {
			$map = [];
			
			foreach ($discover->getDefinitions() as $definition) {
				$className = $definition->className;
				
				// Skip classes that don't exist to avoid fatal errors on reflection
				if (!class_exists($className)) {
					continue;
				}
				
				// Filter by interface using the class name string — no instantiation needed
				if (!is_a($className, SignalProviderInterface::class, true)) {
					continue;
				}
				
				// Reflect the class to enumerate its public methods
				$reflection = new ReflectionClass($className);
				
				foreach ($reflection->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
					// Read @ListenTo annotations from the method without instantiating the class.
					// If the annotation is malformed or unresolvable, skip this method silently.
					try {
						$annotations = $this->annotationReader->getMethodAnnotations(
							$className,
							$method->getName(),
							ListenTo::class
						);
					} catch (AnnotationReaderException $e) {
						continue;
					}
					
					// Store the class name and method rather than a callable — instantiation
					// is deferred to connect() where we know a matching signal exists
					foreach ($annotations as $annotation) {
						$map[$annotation->getName()][] = [
							'className' => $className,
							'method'    => $method->getName(),
							'priority'  => $annotation->getPriority(),
						];
					}
				}
			}
			
			return $map;
		}
	}