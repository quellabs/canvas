<?php
	
	namespace Quellabs\Canvas\Signals;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\ListenTo;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Contracts\SignalProviderInterface;
	use Quellabs\DependencyInjection\Container;
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
		 * @throws AnnotationReaderException
		 */
		public function __construct(Kernel $kernel) {
			$this->annotationReader = $kernel->getAnnotationsReader();
			$this->di = $kernel->getDependencyInjector();
			
			// Fetch path where listeners are stored
			$signalProviderPath = $kernel->getConfiguration()->get(
				"signal_listeners_path",
				ComposerUtils::getProjectRoot() . DIRECTORY_SEPARATOR . "src" . DIRECTORY_SEPARATOR . "Listeners"
			);
			
			// Find all slots
			if (is_dir($signalProviderPath) && is_readable($signalProviderPath)) {
				$slotClasses = ComposerUtils::findClassesInDirectory($signalProviderPath);
			} else {
				$slotClasses = [];
			}
			
			// Scan the filesystem and reflect all provider classes once at construction
			// time. connect() then only does lookups into this pre-built map.
			$this->listenerMap = $this->buildListenerMap($slotClasses);
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
					$instance = $this->di->make($listener['className']);
					
					// Build the callable and verify it at runtime. is_callable() also
					// narrows the type to callable for PHPStan, avoiding a spurious error
					// on the dynamic method name that static analysis cannot verify.
					$callable = [$instance, $listener['method']];
					
					// Only call if it's indeed callable
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
		 * Scans all discovered providers for @ListenTo annotations and builds a
		 * signal-name-keyed map of listener definitions.
		 *
		 * Instantiation is deliberately deferred — only class names and method names
		 * are stored here. The provider instance is resolved from the container in
		 * connect() once we know a matching signal actually exists.
		 *
		 * @param array<string> $classNames
		 * @return ListenerMap
		 * @throws AnnotationReaderException
		 */
		private function buildListenerMap(array $classNames): array {
			$map = [];
			
			foreach ($classNames as $className) {
				// Skip classes that don't exist
				if (!class_exists($className)) {
					continue;
				}
				
				// Reflect the class to enumerate its public methods
				$reflection = new ReflectionClass($className);
				
				foreach ($reflection->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
					// Read @ListenTo annotations from the method without instantiating the class.
					// If the annotation is malformed or unresolvable, skip this method silently.
					$annotations = $this->annotationReader->getMethodAnnotations(
						$className,
						$method->getName(),
						ListenTo::class
					);
					
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