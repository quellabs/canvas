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
	
	/**
	 * Wires signals to their slots using @ListenTo annotations on signal providers.
	 *
	 * Signal providers are discovered via Composer's extra.signal-hub.providers key.
	 * Each provider method annotated with @ListenTo("signal.name") is automatically
	 * connected to the matching signal — no manual connect() implementation needed.
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
		 * @var string $signalProviderPath
		 */
		private string $signalProviderPath;
		
		/**
		 * Discovers signal providers and pre-builds the listener map from @ListenTo annotations.
		 * @param Kernel $kernel
		 */
		public function __construct(Kernel $kernel) {
			// Store annotation reader
			$this->annotationReader = $kernel->getAnnotationsReader();
			$this->di = $kernel->getDependencyInjector();
			$this->signalProviderPath = $kernel->getConfiguration()->get(
				"signal_listeners_path",
				ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "Listeners"
			);
		}
		
		/**
		 * Wire a set of signals to their slots using the pre-built listener map.
		 * Each signal is matched by name; unmatched signals are silently skipped.
		 * @param Signal[] $signals Signals to wire, typically freshly discovered on a controller
		 * @return void
		 */
		public function connect(array $signals): void {
			// Discover providers and build a signal-name-keyed map of listeners
			$slots = $this->discoverSlots();
			$listenerMap = $this->buildListenerMap($slots);
			
			foreach ($signals as $signal) {
				// Look up listeners for this signal by name; skip if none are registered
				$listeners = $listenerMap[$signal->getName()] ?? [];
				
				foreach ($listeners as $listener) {
					// Resolve the provider instance from the container
					$instance = $this->di->get($listener['className']);
					
					// Create the callable
					$callable = [$instance, $listener['method']];
					
					// Validate that the callable is actually callable
					if (!is_callable($callable)) {
						continue;
					}
					
					// Wire the signal to the method
					$signal->connect($callable, $listener['priority']);
				}
			}
		}
		
		/**
		 * Discovers all signal providers registered under the "signal-hub" Composer family,
		 * plus any providers found in the configured local SignalProviders directory.
		 * @return Discover
		 */
		private function discoverSlots(): Discover {
			// Discover all packages that register themselves under the "signal-hub" family
			$discover = new DependencyAwareDiscover($this->di);
			$discover->addScanner(new ComposerScanner("signal-hub"));
			
			// If a local SignalProviders directory exists, scan that too
			if (is_dir($this->signalProviderPath)) {
				$discover->addScanner(new DirectoryScanner([$this->signalProviderPath]));
			}
			
			$discover->discover();
			return $discover;
		}
		
		/**
		 * Scans all discovered providers for @ListenTo annotations and builds a
		 * signal-name-keyed map of callables and their priorities.
		 * @return array<string, array<array{className: class-string<SignalProviderInterface>, method: non-empty-string, priority: mixed}>>
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
					foreach ($annotations->ofType(ListenTo::class) as $annotation) {
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