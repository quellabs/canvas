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
	use Quellabs\SignalHub\Slot;
	use Quellabs\Support\ComposerUtils;
	use ReflectionClass;
	
	/**
	 * Wires signals to their slots using @ListenTo annotations on signal providers.
	 *
	 * Signal providers are discovered via Composer's extra.signal-hub.providers key.
	 * Each provider method annotated with @ListenTo("signal.name") is automatically
	 * connected to the matching signal — no manual connect() implementation needed.
	 *
	 * Slot lifetime:
	 * Signal owns its Slots via a plain array of strong references. Slots created
	 * here do not need to be stored anywhere else — they stay alive for as long as
	 * the Signal does, and are released automatically when the Signal goes out of scope.
	 *
	 * @phpstan-type ListenerDefinition array{
	 *     className: class-string<SignalProviderInterface>,
	 *     method: non-empty-string,
	 *     priority: int
	 * }
	 *
	 * @phpstan-type ListenerMap array<string, array<ListenerDefinition>>
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
		 * Map of signal name → listener definitions, built once in the constructor.
		 * Keyed by signal name; each entry is a list of className/method/priority tuples.
		 * @var ListenerMap
		 */
		private array $listenerMap;
		
		/**
		 * Discovers signal providers and builds the listener map from @ListenTo annotations.
		 * The filesystem scan and reflection happen here, once, at a known point during
		 * bootstrap — not on the first connect() call.
		 * @param Kernel $kernel
		 */
		public function __construct(Kernel $kernel) {
			$this->annotationReader = $kernel->getAnnotationsReader();
			$this->di = $kernel->getDependencyInjector();
			
			$signalProviderPath = $kernel->getConfiguration()->get(
				"signal_listeners_path",
				ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "Listeners"
			);
			
			// Scan the filesystem and reflect all provider classes once at construction
			// time. connect() then only does lookups into this pre-built map.
			$this->listenerMap = $this->buildListenerMap($this->discoverSlots($signalProviderPath));
		}
		
		/**
		 * Wire a set of signals to their slots using @ListenTo annotations.
		 *
		 * Each signal is matched by name against the pre-built listener map;
		 * unmatched signals are silently skipped.
		 *
		 * Slots are created inline — no external reference is needed. Signal holds
		 * strong references to all connected Slots internally.
		 *
		 * @param Signal[] $signals Signals to wire, typically freshly discovered on a controller
		 * @return void
		 */
		public function connect(array $signals): void {
			foreach ($signals as $signal) {
				// Look up listeners for this signal by name; skip if none are registered
				$listeners = $this->listenerMap[$signal->getName()] ?? [];
				
				foreach ($listeners as $listener) {
					// Resolve the provider instance from the container
					$instance = $this->di->get($listener['className']);
					
					// Class could not be resolved — skip silently
					if ($instance === null) {
						continue;
					}
					
					// Build the callable and verify it at runtime. is_callable() also
					// narrows the type to callable for PHPStan, avoiding a spurious error
					// on the dynamic method name that static analysis cannot verify.
					$callable = [$instance, $listener['method']];

					if (!is_callable($callable)) {
						continue;
					}

					// Signal owns the Slot strongly via its internal array, so no
					// external reference is needed to keep it alive
					$signal->connect(new Slot($callable), $listener['priority']);
				}
			}
		}
		
		/**
		 * Discovers all signal providers registered under the "signal-hub" Composer family,
		 * plus any providers found in the configured local listeners directory.
		 * @param string $signalProviderPath Path to scan for local listener classes
		 * @return Discover
		 */
		private function discoverSlots(string $signalProviderPath): Discover {
			// Discover all packages that register themselves under the "signal-hub" family
			$discover = new DependencyAwareDiscover($this->di);
			$discover->addScanner(new ComposerScanner("signal-hub"));
			
			// If a local listeners directory exists, scan that too
			if (is_dir($signalProviderPath)) {
				$discover->addScanner(new DirectoryScanner([$signalProviderPath]));
			}
			
			$discover->discover();
			return $discover;
		}
		
		/**
		 * Scans all discovered providers for @ListenTo annotations and builds a
		 * signal-name-keyed map of listener definitions.
		 *
		 * Instantiation is deliberately deferred — only class names and method names
		 * are stored here. The provider instance is resolved from the container in
		 * connect() once we know a matching signal actually exists.
		 *
		 * @param Discover $discover
		 * @return ListenerMap
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