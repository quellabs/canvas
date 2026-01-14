<?php
	
	/*
	 * ╔══════════════════════════════════════════════════════════════════════════════════════╗
	 * ║                                                                                      ║
	 * ║     ██████╗ █████╗ ███╗   ██╗██╗   ██╗ █████╗ ███████╗                               ║
	 * ║    ██╔════╝██╔══██╗████╗  ██║██║   ██║██╔══██╗██╔════╝                               ║
	 * ║    ██║     ███████║██╔██╗ ██║██║   ██║███████║███████╗                               ║
	 * ║    ██║     ██╔══██║██║╚██╗██║╚██╗ ██╔╝██╔══██║╚════██║                               ║
	 * ║    ╚██████╗██║  ██║██║ ╚████║ ╚████╔╝ ██║  ██║███████║                               ║
	 * ║     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝                               ║
	 * ║                                                                                      ║
	 * ║  Canvas - A lightweight, modern PHP framework built for real-world projects          ║
	 * ║                                                                                      ║
	 * ║  Drop into existing PHP projects without rewriting routes or structure. Features     ║
	 * ║  annotation-based routing, contextual dependency injection, ObjectQuel ORM, and      ║
	 * ║  aspect-oriented programming. No magic, no bloat — just the tools you need.          ║
	 * ║                                                                                      ║
	 * ╚══════════════════════════════════════════════════════════════════════════════════════╝
	 */
	
	namespace Quellabs\Canvas;
	
	use Quellabs\AnnotationReader\AnnotationReader;
	use Quellabs\Canvas\Configuration\Configuration;
	use Quellabs\Canvas\Routing\RequestHandler;
	use Quellabs\Canvas\Inspector\EventCollector;
	use Quellabs\Canvas\Discover\AnnotationsReaderProvider;
	use Quellabs\Canvas\Discover\CacheInterfaceProvider;
	use Quellabs\Canvas\Discover\ConfigurationProvider;
	use Quellabs\Canvas\Discover\DiscoverProvider;
	use Quellabs\Canvas\Discover\KernelProvider;
	use Quellabs\Canvas\Discover\SignalHubProvider;
	use Quellabs\Canvas\Inspector\Inspector;
	use Quellabs\Canvas\Legacy\LegacyBridge;
	use Quellabs\Canvas\Legacy\LegacyHandler;
	use Quellabs\DependencyInjection\Container;
	use Quellabs\DependencyInjection\Provider\SimpleBinding;
	use Quellabs\Discover\Discover;
	use Quellabs\SignalHub\HasSignals;
	use Quellabs\SignalHub\Signal;
	use Quellabs\SignalHub\SignalHub;
	use Quellabs\SignalHub\SignalHubLocator;
	use Quellabs\Support\ComposerUtils;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	class Kernel {
		
		use HasSignals;
		
		private Signal $canvasQuerySignal; // Signal for performance measuring
		private Discover $discover; // Service discovery
		private AnnotationReader $annotationsReader; // Annotation reading
		private Configuration $configuration;
		private Configuration $inspector_configuration;
		private ?array $contents_of_app_php = null;
		private bool $legacyEnabled;
		private ?LegacyHandler $legacyFallbackHandler;
		private Container $dependencyInjector;
		
		/**
		 * Kernel constructor
		 * @param array $configuration
		 */
		public function __construct(array $configuration = []) {
			// Connect SignalHub to this class
			$this->setSignalHub(SignalHubLocator::getInstance());
			$this->canvasQuerySignal = $this->createSignal(['array'], 'debug.canvas.query');
			
			// Register Discovery service
			$this->discover = new Discover();
			
			// Store the configuration array
			$this->configuration = new Configuration(array_merge($this->getConfigFile("app.php"), $configuration));
			$this->inspector_configuration = new Configuration($this->getConfigFile("inspector.php"));
			
			// Register Annotations Reader
			$this->annotationsReader = $this->createAnnotationReader();
			
			// Instantiate Dependency Injector and register default providers
			$this->dependencyInjector = new Container();
			$this->dependencyInjector->register(new SimpleBinding(Kernel::class, $this));
			$this->dependencyInjector->register(new SimpleBinding(Configuration::class, $this->configuration));
			$this->dependencyInjector->register(new SimpleBinding(Discover::class, $this->discover));
			$this->dependencyInjector->register(new SimpleBinding(SignalHub::class, SignalHubLocator::getInstance()));
			$this->dependencyInjector->register(new SimpleBinding(AnnotationReader::class, $this->annotationsReader));
			$this->dependencyInjector->register(new CacheInterfaceProvider($this->dependencyInjector, $this->annotationsReader));
			
			// Initialize legacy fallback handler to null explicitly to please phpstan
			$this->legacyFallbackHandler = null;
			
			// Initialize legacy support
			$this->initializeLegacySupport();
			
			// Add a custom exception handler for some nicer exception messages
			set_exception_handler([$this, 'customExceptionHandler']);
		}
		
		/**
		 * Returns the AnnotationReader object
		 * @return AnnotationReader
		 */
		public function getAnnotationsReader(): AnnotationReader {
			return $this->annotationsReader;
		}
		
		/**
		 * Returns the Configuration object
		 * @return Configuration
		 */
		public function getConfiguration(): Configuration {
			return $this->configuration;
		}
		
		/**
		 * Returns the Configuration object for the inspector
		 * @return Configuration
		 */
		public function getInspectorConfiguration(): Configuration {
			return $this->inspector_configuration;
		}
		
		/**
		 * Returns the Container object
		 * @return Container
		 */
		public function getDependencyInjector(): Container {
			return $this->dependencyInjector;
		}
		
		/**
		 * Returns true if legacy fallback is enabled
		 * @return bool
		 */
		public function isLegacyEnabled(): bool {
			return $this->legacyEnabled;
		}
		
		/**
		 * Returns the legacy fallback handler object
		 * @return LegacyHandler|null
		 */
		public function getLegacyHandler(): ?LegacyHandler {
			return $this->legacyFallbackHandler;
		}
		
		/**
		 * Custom handler for exceptions
		 * @param \Throwable $exception
		 * @return void
		 */
		public function customExceptionHandler(\Throwable $exception): void {
			// Clear any previous output
			if (ob_get_level()) {
				ob_end_clean();
			}
			
			// Create error response using the existing method
			$response = $this->createErrorResponse($exception);
			
			// Send the response
			$response->send();
			
			// Exit
			exit(1);
		}
		
		/**
		 * Process an HTTP request through the controller system and return the response
		 * @param Request $request The incoming HTTP request object
		 * @return Response HTTP response to be sent back to the client
		 * @throws \Exception
		 */
		public function handle(Request $request): Response {
			// Performance monitoring
			$start = microtime(true);
			$memoryStart = memory_get_usage(true);
			
			// Initialize debug data collection system for development environments
			// This collector will gather performance metrics, query logs, and debugging info
			$debugBarEnabled = $this->getInspectorConfiguration()->get('enabled', false);
			$debugCollector = $debugBarEnabled ? new EventCollector(SignalHubLocator::getInstance()) : null;

			// Initialize URL parsing variables
			$urlData = null;
			$isLegacyPath = false;
			
			// Delegation pattern: RequestHandler contains the core routing and controller logic
			$requestHandler = new RequestHandler($this);
			
			// Process the request through the routing system
			$response = $requestHandler->handle($request, $urlData, $isLegacyPath);
			
			// Inject debugging information into the response for development
			$this->injectDebugBar($debugCollector, $request, $response, $urlData, $isLegacyPath, $start, $memoryStart);
			
			// Return the final HTTP response object to be sent to the client
			return $response;
		}
		
		/**
		 * Inject debug bar into response if debug collector is available
		 * @param EventCollector|null $debugCollector Debug collector instance
		 * @param Request $request The HTTP request
		 * @param Response $response The HTTP response to inject into
		 * @param array|null $urlData URL resolution data
		 * @param bool $isLegacyPath Whether this was handled by legacy system
		 * @param float $start Request start time
		 * @param int $memoryStart Initial memory usage
		 */
		private function injectDebugBar(
			?EventCollector $debugCollector,
			Request         $request,
			Response        $response,
			?array          $urlData,
			bool            $isLegacyPath,
			float           $start,
			int             $memoryStart
		): void {
			// Do nothing when the debug collector is not activated
			if (!$debugCollector) {
				return;
			}
			
			// Route
			if ($isLegacyPath || $urlData === null) {
				$pattern = '';
			} else {
				$pattern = $urlData['route']?->getRoute();
			}
			
			// Send signal for performance monitoring
			$this->canvasQuerySignal->emit([
				'request'           => $request,
				'legacy_path'       => $isLegacyPath,
				'http_methods'      => $urlData['http_methods'] ?? null,
				'controller'        => $urlData['controller'] ?? null,
				'method'            => $urlData['method'] ?? null,
				'pattern'           => $pattern,
				'parameters'        => $urlData['variables'] ?? null,
				'execution_time_ms' => (microtime(true) - $start) * 1000,
				'memory_used_bytes' => memory_get_usage(true) - $memoryStart
			]);
			
			// Inject the debug bar
			$debugBar = new Inspector($debugCollector, $this->getInspectorConfiguration());
			$debugBar->inject($request, $response);
		}
		
		/**
		 * Create an error response from an exception
		 * @param \Throwable $exception
		 * @return Response
		 */
		public function createErrorResponse(\Throwable $exception): Response {
			$isDevelopment = $this->configuration->getAs('debug_mode', 'bool', false);
			
			if ($isDevelopment) {
				// In development, show detailed error information as HTML
				$content = $this->renderDebugErrorPageContent($exception);
				return new Response($content, Response::HTTP_INTERNAL_SERVER_ERROR, ['Content-Type' => 'text/html']);
			}
			
			// In production, try to include a simple 500.php file if it exists
			$legacyPath = $this->configuration->get('legacy_path', 'legacy/');
			$errorFile = $legacyPath . '500.php';
			
			if (file_exists($errorFile)) {
				ob_start();
				include $errorFile;
				$content = ob_get_clean();
				return new Response($content, Response::HTTP_INTERNAL_SERVER_ERROR);
			}
			
			// Ultimate fallback - simple HTML page
			$content = $this->renderProductionErrorPageContent();
			return new Response($content, Response::HTTP_INTERNAL_SERVER_ERROR, ['Content-Type' => 'text/html']);
		}
		
		/**
		 * Convert the kernel instance to a string representation.
		 * @return string A formatted string containing kernel mode, legacy status, and root path
		 */
		public function __toString(): string {
			// Determine legacy feature status - convert boolean to readable string
			$legacyStatus = $this->legacyEnabled ? 'enabled' : 'disabled';
			
			// Get debug mode from configuration with fallback to production mode
			// Uses type-safe configuration retrieval with default value
			$debugMode = $this->configuration->getAs('debug_mode', 'bool', false) ? 'debug' : 'production';
			
			// Return formatted kernel information string
			// Format: Canvas\Kernel[mode=debug/production, legacy=enabled/disabled, root=/path/to/project]
			return sprintf(
				'Canvas\Kernel[mode=%s, legacy=%s, root=%s]',
				$debugMode,
				$legacyStatus,
				ComposerUtils::getProjectRoot()
			);
		}
		
		/**
		 * Provide debug information when var_dump() or similar functions are called.
		 * @return array Associative array containing debug-relevant kernel properties
		 */
		public function __debugInfo(): array {
			return [
				// Project root directory path
				'project_root'   => ComposerUtils::getProjectRoot(),
				
				// Current debug mode setting (boolean from configuration)
				'debug_mode'     => $this->configuration->getAs('debug_mode', 'bool', false),
				
				// Whether legacy features are enabled
				'legacy_enabled' => $this->legacyEnabled,
				
				// List of all available configuration keys (for inspecting what's configured)
				'config_keys'    => array_keys($this->configuration->all()),
			];
		}
		
		/**
		 * Creates and configures an AnnotationReader instance with optimized caching settings.
		 * @return AnnotationReader Configured annotation reader instance
		 */
		private function createAnnotationReader(): AnnotationReader {
			// Initialize the annotation reader configuration object
			$config = new \Quellabs\AnnotationReader\Configuration();
			
			// Check if we're NOT in debug mode (i.e., in production or staging)
			if (!$this->configuration->getAs('debug_mode', 'bool', false)) {
				// Get the project root directory path for cache storage
				$rootPath = ComposerUtils::getProjectRoot();
				
				// Enable annotation caching for better performance in production
				$config->setUseAnnotationCache(true);
				
				// Set the cache directory path within the project's storage folder
				$config->setAnnotationCachePath($rootPath . "/storage/annotations");
			}
			
			// Create and return the configured AnnotationReader instance
			return new AnnotationReader($config);
		}
		
		/**
		 * Load app.php
		 * @return array
		 */
		private function getConfigFile(string $filename): array {
			// Fetch from cache if we can
			if (isset($this->contents_of_app_php[$filename])) {
				return $this->contents_of_app_php[$filename];
			}
			
			// Fetch the project root
			$projectRoot = ComposerUtils::getProjectRoot();
			
			// If the config file can't be loaded, return an empty array
			if (
				!file_exists($projectRoot . "/config/{$filename}") ||
				!is_readable($projectRoot . "/config/{$filename}")
			) {
				return $this->contents_of_app_php[$filename] = [];
			}
			
			// Otherwise, grab the contents
			$this->contents_of_app_php[$filename] = require $projectRoot . "/config/{$filename}";
			
			// And return them
			return $this->contents_of_app_php[$filename];
		}
		
		/**
		 * Initialize the legacy support system
		 * @return void
		 */
		private function initializeLegacySupport(): void {
			// Check if legacy fallthrough is enabled
			$this->legacyEnabled = $this->configuration->getAs('legacy_enabled', 'bool', false);
			
			if ($this->legacyEnabled) {
				// Only initialize bridge when legacy support is enabled
				LegacyBridge::initialize($this->dependencyInjector);
				
				// Fetch the legacy path
				$legacyPath = $this->configuration->get('legacy_path', ComposerUtils::getProjectRoot() . '/legacy/');
				
				// Fetch the legacy path
				$preprocessingEnabled = $this->configuration->get('legacy_preprocessing', true);
				
				// Fetch exclusion directories
				$exclusionPaths = $this->configuration->get('exclusion_paths', []);
				
				// Create the fallthrough handler
				$this->legacyFallbackHandler = new LegacyHandler($legacyPath, $preprocessingEnabled, $exclusionPaths);
			}
		}
		
		/**
		 * Render detailed error page content for development
		 * @param \Throwable $exception
		 * @return string
		 */
		private function renderDebugErrorPageContent(\Throwable $exception): string {
			$errorCode = $exception->getCode();
			$errorMessage = $exception->getMessage();
			$errorFile = $exception->getFile();
			$errorLine = $exception->getLine();
			$trace = $exception->getTraceAsString();
			
			return "<!DOCTYPE html>
<html lang='eng'>
<head>
    <title>Canvas Framework Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .error-box { background: white; padding: 20px; border-left: 5px solid #dc3545; }
        .error-title { color: #dc3545; margin: 0 0 20px 0; }
        .error-message { font-size: 18px; margin-bottom: 20px; }
        .error-details { background: #f8f9fa; padding: 15px; border-radius: 4px; }
        .trace { background: #2d2d2d; color: #f8f8f2; padding: 15px; overflow-x: auto; font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class='error-box'>
        <h1 class='error-title'>Canvas Framework Error</h1>
        <div class='error-message'>" . htmlspecialchars($errorMessage) . "</div>
        <div class='error-details'>
            <strong>File:</strong> " . htmlspecialchars($errorFile) . "<br>
            <strong>Line:</strong> " . $errorLine . "<br>
            <strong>Code:</strong> " . $errorCode . "
        </div>
        <h3>Stack Trace:</h3>
        <pre class='trace'>" . htmlspecialchars($trace) . "</pre>
    </div>
</body>
</html>";
		}
		
		/**
		 * Render generic error page content for production
		 * @return string
		 */
		private function renderProductionErrorPageContent(): string {
			return "<!DOCTYPE html>
<html lang='eng'>
<head>
    <title>Server Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; text-align: center; }
        .error-box { background: white; padding: 40px; border-radius: 8px; display: inline-block; }
        .error-title { color: #dc3545; margin: 0 0 20px 0; }
    </style>
</head>
<body>
    <div class='error-box'>
        <h1 class='error-title'>Server Error</h1>
        <p>Something went wrong. Please try again later.</p>
        <p>If the problem persists, please contact support.</p>
    </div>
</body>
</html>";
		}
	}