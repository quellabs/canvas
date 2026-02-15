<?php
	
	namespace Quellabs\Canvas\Routing;
	
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\AOP\AspectDispatcher;
	use Quellabs\Canvas\Discover\MethodContextProvider;
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\Context\MethodContext;
	use Quellabs\DependencyInjection\Provider\SimpleBinding;
	use Quellabs\Support\ComposerUtils;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\Session\Session;
	use Symfony\Component\HttpFoundation\Session\SessionInterface;
	
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
		 * @param array|null $urlData
		 * @param bool $isLegacyPath
		 * @return Response HTTP response to be sent back to the client
		 * @throws AnnotationReaderException|RouteNotFoundException
		 */
		public function handle(Request $request, ?array &$urlData, bool &$isLegacyPath): Response {
			// Initialize variables to track route resolution and performance metrics
			$urlData = null;           // Will hold resolved route data if found
			$isLegacyPath = false;     // Flag to track if legacy routing was used
			
			// Set up request environment and get service providers
			$providers = $this->prepareRequest($request);
			
			try {
				$response = $this->modernResolve($request, $urlData);
			} catch (RouteNotFoundException $e) {
				// Check if legacy routing is enabled and a handler is configured
				// If not, rethrow the exception
				if (!$this->kernel->isLegacyEnabled() || !$this->kernel->getLegacyHandler()) {
					// No legacy fallback configured,
					throw $e;
				}
				
				// Resolve the legacy path
				$response = $this->legacyResolve($request, $isLegacyPath);
			} finally {
				// Always clean up request resources, regardless of success/failure
				$this->cleanupRequest($providers);
			}
			
			// Return the final HTTP response to be sent to the client
			return $response;
		}
		
		/**
		 * Prepare the request for processing by ensuring session availability and registering providers
		 * @param Request $request The incoming HTTP request
		 * @return array Array containing the registered providers for cleanup
		 */
		private function prepareRequest(Request $request): array {
			// Check if session exists, create if needed
			if (!$request->hasSession()) {
				$request->setSession(new Session());
			}
			
			// Register providers with dependency injector for this request lifecycle
			$requestProvider = new SimpleBinding(Request::class, $request);
			$sessionProvider = new SimpleBinding(SessionInterface::class, $request->getSession());
			$this->kernel->getDependencyInjector()->register($requestProvider);
			$this->kernel->getDependencyInjector()->register($sessionProvider);
			
			// Return providers for cleanup in finally block
			return [
				'request' => $requestProvider,
				'session' => $sessionProvider
			];
		}
		
		/**
		 * Clean up registered providers from the dependency injector
		 * @param array $providers Array of providers to unregister
		 */
		private function cleanupRequest(array $providers): void {
			$this->kernel->getDependencyInjector()->unregister($providers['session']);
			$this->kernel->getDependencyInjector()->unregister($providers['request']);
		}
		
		/**
		 * Resolves routes using modern annotation-based routing system
		 * @param Request $request The incoming HTTP request to resolve
		 * @param array|null $urlData Reference parameter to store resolved route data         *
		 * @return Response The response from the matched route handler
		 * @param-out array $urlData The resolved URL data (never null after execution)
		 * @throws RouteNotFoundException When no matching route is found
		 * @throws AnnotationReaderException When annotation parsing fails
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
		 * @param bool $isLegacyPath Reference parameter - set to true if legacy routing is used
		 * @return Response The response from legacy handler or 404 if routing fails
		 * @throws RouteNotFoundException
		 */
		private function legacyResolve(Request $request, bool &$isLegacyPath): Response {
			// Mark that we're using legacy routing for this request
			$isLegacyPath = true;
			
			// Delegate to the legacy routing handler
			return $this->kernel->getLegacyHandler()->handle($request);
		}
	
		/**
		 * Execute a Canvas route
		 * Creates MethodContext and registers it with DI for autowiring
		 * @param Request $request
		 * @param array $urlData
		 * @return Response
		 * @throws AnnotationReaderException
		 */
		private function executeCanvasRoute(Request $request, array $urlData): Response {
			// Get the controller instance from the dependency injection container
			$controller = $this->kernel->getDependencyInjector()->get($urlData["controller"]);
			
			// Create method context containing all execution metadata
			$context = new MethodContext(
				request: $request,
				target: $controller,
				methodName: $urlData["method"],
				arguments: $urlData["variables"],
				pattern: $urlData["pattern"]
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
			}
		}
	}