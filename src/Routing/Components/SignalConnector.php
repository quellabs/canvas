<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\Annotations\ListenTo;
	use Quellabs\Canvas\Discover\DependencyAwareDiscover;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Contracts\SignalProviderInterface;
	use Quellabs\DependencyInjection\Container;
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
		 * @var array Signal provider instances discovered from composer packages
		 */
		private array $connectors;
		
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
			$discover = new DependencyAwareDiscover($this->di);
			$discover->addScanner(new ComposerScanner("signal-hub"));
			$discover->addScanner(new DirectoryScanner([$signalProviderPath]));
			$discover->discover();
			
			// Keep only providers that implement the expected contract
			$this->connectors = array_filter(
				iterator_to_array($discover->getProviders()),
				fn($provider) => $provider instanceof SignalProviderInterface
			);
			
			// Scan annotations once and cache the result — connect() is a hot path
			$this->listenerMap = $this->buildListenerMap();
		}
		
		/**
		 * Wire a set of signals to their slots using the pre-built listener map.
		 * Each signal is matched by name; unmatched signals are silently skipped.
		 * @param Signal[] $signals Signals to wire, typically freshly discovered on a controller
		 * @return void
		 */
		public function connect(array $signals): void {
			foreach ($signals as $signal) {
				foreach ($this->listenerMap[$signal->getName()] ?? [] as $listener) {
					$signal->connect($listener['callable'], $listener['priority']);
				}
			}
		}
		
		/**
		 * Scans all discovered providers for @ListenTo annotations and builds a
		 * signal-name-keyed map of callables and their priorities.
		 * @return array<string, array<array{callable: callable, priority: int}>>
		 */
		private function buildListenerMap(): array {
			$map = [];
			
			foreach ($this->connectors as $connector) {
				// Reflect the provider class. If the provider class
				// is not reflectable; skip it entirely
				try {
					$reflection = new ReflectionClass($connector);
				} catch (ReflectionException $e) {
					continue;
				}
				
				// Fetch all methods
				foreach ($reflection->getMethods() as $method) {
					// Ignore private/protected methods.
					if (!$method->isPublic()) {
						continue;
					}
					
					// Read all ListenTo annotations from the method
					// If malformed or unresolvable annotation on this method; skip it
					try {
						$annotations = $this->annotationReader->getMethodAnnotations(
							$connector,
							$method->getName(),
							ListenTo::class
						);
					} catch (AnnotationReaderException $e) {
						continue;
					}
					
					// Store information in a map
					foreach ($annotations as $annotation) {
						$map[$annotation->getName()][] = [
							'callable' => [$connector, $method->getName()],
							'priority' => $annotation->getPriority(),
						];
					}
				}
			}
			
			return $map;
		}
	}