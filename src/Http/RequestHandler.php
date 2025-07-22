<?php
	
	namespace Quellabs\Canvas\Http;
	
	use Quellabs\AnnotationReader\Exception\AnnotationReaderException;
	use Quellabs\Canvas\AOP\AspectDispatcher;
	use Quellabs\Canvas\Discover\RequestProvider;
	use Quellabs\Canvas\Discover\SessionInterfaceProvider;
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Routing\AnnotationResolver;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	use Symfony\Component\HttpFoundation\Session\Session;
	
	class RequestHandler {

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
		 */
		public function handle(Request $request, ?array &$urlData, bool &$isLegacyPath): Response {
			// Initialize variables to track route resolution and performance metrics
			$urlData = null;           // Will hold resolved route data if found
			$isLegacyPath = false;     // Flag to track if legacy routing was used
			
			// Set up request environment and get service providers
			$providers = $this->prepareRequest($request);
			
			try {
				try {
					$response = $this->modernResolve($request, $urlData);
				} catch (RouteNotFoundException $e) {
					$response = $this->legacyResolve($request, $isLegacyPath);
				}
			} catch (\Exception $e) {
				// Handle any unexpected errors during request processing
				$response = $this->kernel->createErrorResponse($e);
				$isLegacyPath = false;
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
			$requestProvider = new RequestProvider($request);
			$sessionProvider = new SessionInterfaceProvider($request->getSession());
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
		 * @param array|null $urlData Reference parameter to store resolved route data
		 * @return Response The response from the matched route handler
		 * @throws RouteNotFoundException When no matching route is found
		 * @throws AnnotationReaderException When annotation parsing fails
		 */
		private function modernResolve(Request $request, ?array &$urlData = null): Response {
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
		 */
		private function legacyResolve(Request $request, bool &$isLegacyPath): Response {
			// Check if legacy routing is enabled and a handler is configured
			if (!$this->kernel->isLegacyEnabled() || !$this->kernel->getLegacyHandler()) {
				// No legacy fallback configured, return 404 response
				return $this->createNotFoundResponse($request, $this->kernel->isLegacyEnabled());
			}
			
			try {
				// Mark that we're using legacy routing for this request
				$isLegacyPath = true;
				
				// Delegate to the legacy routing handler
				return $this->kernel->getLegacyHandler()->handle($request);
			} catch (RouteNotFoundException $e) {
				// Legacy routing also failed - return 404 response
				return $this->createNotFoundResponse($request, $this->kernel->isLegacyEnabled());
			}
		}
		
		/**
		 * Execute a Canvas route
		 * @param Request $request
		 * @param array $urlData
		 * @return Response
		 * @throws AnnotationReaderException
		 */
		private function executeCanvasRoute(Request $request, array $urlData): Response {
			// Get the controller instance from the dependency injection container
			$controller = $this->kernel->getDependencyInjector()->get($urlData["controller"]);
			
			// Create aspect-aware dispatcher
			$aspectDispatcher = new AspectDispatcher($this->kernel->getAnnotationsReader(), $this->kernel->getDependencyInjector());
			
			// Run the request through the aspect dispatcher
			return $aspectDispatcher->dispatch(
				$request,
				$controller,
				$urlData["method"],
				$urlData["variables"]
			);
		}
		
		/**
		 * Create a 404 Not Found response
		 * @param Request $request The Request object
		 * @param bool $legacyAttempted Whether legacy fallthrough was attempted
		 * @return Response
		 */
		private function createNotFoundResponse(Request $request, bool $legacyAttempted = false): Response {
			$isDevelopment = $this->kernel->getConfiguration()->getAs('debug_mode', 'bool', false);
			$legacyPath = $this->kernel->getDiscover()->normalizePath($this->kernel->getConfiguration()->get('legacy_path', $this->kernel->getDiscover()->getProjectRoot() . DIRECTORY_SEPARATOR . 'legacy'));
			$notFoundFile = $legacyPath . '404.php';
			
			if ($isDevelopment) {
				// In development, show helpful debug information
				if ($legacyAttempted) {
					$legacyMessage = "No Canvas route found. Legacy fallback also has no matching file.\n\n";
				} elseif ($this->kernel->isLegacyEnabled()) {
					$legacyMessage = "No Canvas route found. No matching legacy file exists.\n\n";
				} else {
					$legacyMessage = "No Canvas route found.\n\n";
				}
				
				if ($this->kernel->isLegacyEnabled() && file_exists($notFoundFile)) {
					$customizationHelp = "Custom 404 file found at: {$notFoundFile}\n- This will be used in production mode\n- Or add a Canvas route for this path";
				} elseif ($this->kernel->isLegacyEnabled()) {
					$customizationHelp = "To customize this page:\n- Create a 404.php file in your legacy directory ({$legacyPath})\n- Or add a Canvas route for this path";
				} else {
					$customizationHelp = "To customize this page:\n- Add a Canvas route for this path\n- Or enable legacy mode and create a 404.php file";
				}
				
				$content = sprintf(
					"404 Not Found\n\nRequested: %s %s\n\n%s%s",
					$request->getMethod(),
					$request->getPathInfo(),
					$legacyMessage,
					$customizationHelp
				);
				
				return new Response($content, Response::HTTP_NOT_FOUND, ['Content-Type' => 'text/plain']);
			}
			
			// In production, try to include a custom 404.php file if it exists and legacy is enabled
			if ($this->kernel->isLegacyEnabled() && file_exists($notFoundFile)) {
				ob_start();
				include $notFoundFile;
				$content = ob_get_clean();
				return new Response($content, Response::HTTP_NOT_FOUND);
			}
			
			// Ultimate fallback - simple text
			return new Response('Page not found', Response::HTTP_NOT_FOUND);
		}
	}