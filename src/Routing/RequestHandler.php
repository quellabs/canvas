<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\Canvas\Signals\SignalConnector;
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\AOP\AspectDispatcher;
	use Quellabs\Canvas\Discover\MethodContextProvider;
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Context\MethodContext;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * @phpstan-import-type MatchedRoute from RouteTypes
	 */
	class RequestHandler {
		
		/** @var Kernel Application kernel */
		private Kernel $kernel;
		
		/**
		 * RequestHandler constructor
		 * @param Kernel $kernel
		 */
		public function __construct(Kernel $kernel) {
			$this->kernel = $kernel;
		}
		
		/**
		 * Process an HTTP request through the controller system and return the response
		 * @param Request $request The incoming HTTP request object
		 * @param array<string, mixed>|null $urlData
		 * @return Response HTTP response to be sent back to the client
		 * @throws AnnotationReaderException|RouteNotFoundException|\ReflectionException
		 * @throws \Exception
		 */
		public function handle(Request $request, ?array &$urlData): Response {
			try {
				return $this->modernResolve($request, $urlData);
			} catch (RouteNotFoundException $e) {
				if (!$this->kernel->isLegacyEnabled()) {
					throw $e;
				}
				
				return $this->legacyResolve($request);
			}
		}
		
		/**
		 * Resolves routes using modern annotation-based routing system
		 * @param Request $request The incoming HTTP request to resolve
		 * @param array<string, mixed>|null $urlData Null on entry, populated with resolved route data on return
		 * @param-out MatchedRoute $urlData The resolved URL data (never null after execution)
		 * @return Response The response from the matched route handler
		 * @throws RouteNotFoundException When no matching route is found
		 * @throws AnnotationReaderException|\ReflectionException When annotation parsing fails
		 */
		private function modernResolve(Request $request, ?array &$urlData): Response {
			// Create resolver to handle annotation-based route discovery
			$urlResolver = new AnnotationResolver($this->kernel);
			
			// Attempt to resolve the request URL to a controller/action
			$urlData = $urlResolver->resolve($request);
			
			// Execute the resolved route and get the response
			return $this->executeCanvasRoute($request, $urlData);
		}
		
		/**
		 * Fallback to legacy routing system when modern resolution fails
		 * @param Request $request The incoming HTTP request to resolve
		 * @return Response The response from legacy handler or 404 if routing fails
		 * @throws \Exception
		 */
		private function legacyResolve(Request $request): Response {
			return $this->kernel->getLegacyHandler()->handle($request);
		}
		
		/**
		 * Execute a Canvas route
		 * Creates MethodContext and registers it with DI for autowiring
		 * @param Request $request
		 * @param MatchedRoute $urlData
		 * @return Response
		 * @throws AnnotationReaderException
		 * @throws \ReflectionException
		 */
		private function executeCanvasRoute(Request $request, array $urlData): Response {
			// Get the controller instance from the dependency injection container
			$dependencyInjector = $this->kernel->getDependencyInjector();
			
			/** @var class-string $controllerClass */
			$controllerClass = $urlData["controller"];
			$controller = $dependencyInjector->make($controllerClass);
			
			// Register controller signals with the hub
			$hub = $this->kernel->getSignalHub();
			$signals = $hub->discoverSignals($controller);
			
			// If signals found, auto-connect them to slots
			if (!empty($signals)) {
				$connector = new SignalConnector($this->kernel);
				$connector->connect($signals);
			}
			
			// Create method context containing all execution metadata
			$context = new MethodContext(
				request: $request,
				target: $controller,
				methodName: $urlData["method"],
				arguments: $urlData["variables"]
			);
			
			// Register context with DI for autowiring into services
			$methodContextProvider = new MethodContextProvider($context);
			$this->kernel->getDependencyInjector()->register($methodContextProvider);
			
			try {
				// Create aspect-aware dispatcher
				$aspectDispatcher = new AspectDispatcher(
					$this->kernel->getAnnotationsReader(),
					$this->kernel->getDependencyInjector()
				);
				
				// Run the request through the aspect dispatcher
				return $aspectDispatcher->dispatch($context);
				
			} finally {
				// Always unregister context, even if exception occurs
				$this->kernel->getDependencyInjector()->unregister($methodContextProvider);
				
				// Unregister signals
				$hub->unregisterSignals($controller);
			}
		}
	}