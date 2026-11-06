<?php
	
	namespace Quellabs\Canvas\Legacy;
	
	use Quellabs\Contracts\DependencyInjection\ContainerInterface;
	use Quellabs\Support\ComposerUtils;
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Legacy\Resolvers\DefaultFileResolver;
	use Symfony\Component\HttpFoundation\RedirectResponse;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Handles fallthrough routing for legacy PHP files when modern routes don't match.
	 * This allows gradual migration from legacy PHP files to modern framework routes.
	 *
	 * Deployment requirement: executeLegacyFile() uses a process-wide chdir() and relies
	 * on process-wide globals ($__canvas_headers, superglobals) that are reset per request
	 * but not isolated between requests running concurrently in the same process. This is
	 * safe under a one-request-per-process model (PHP-FPM, mod_php, CLI server) but not
	 * under a coroutine/persistent-worker runtime (e.g. Swoole) serving concurrent requests
	 * on the same worker.
	 */
	class LegacyHandler {
		
		/** @var FileResolverInterface[] Array of file resolvers to try in order */
		private array $resolvers = [];
		
		/** @var string Base path where legacy files are located */
		private string $legacyPath;
		
		/** @var bool True if we should preprocess the legacy php file */
		private bool $preprocessingEnabled;
		
		/** @var RecursiveLegacyPreprocessor Optional preprocessor for handling exit() and headers */
		private RecursiveLegacyPreprocessor $preprocessor;
		
		/**
		 * Cache directory for preprocessed legacy PHP files
		 * @var string
		 */
		private string $cacheDir;

		/**
		 * DI container used to autowire configured resolver classes; null falls
		 * back to constructing them with only $legacyPath
		 * @var ContainerInterface|null
		 */
		private ?ContainerInterface $container;

		/**
		 * Initialize the handler with a base legacy path.
		 * @param string $legacyPath Base directory path for legacy files
		 * @param bool $preprocessingEnabled
		 * @param array<string> $excludedPaths Additional path segments to exclude from preprocessing; a 'vendor' segment is always excluded
		 * @param array<class-string<FileResolverInterface>> $resolverClasses Resolver classes to instantiate with $legacyPath, tried in the given order
		 * @param ContainerInterface|null $container Autowires each resolver's other constructor dependencies, if given
		 */
		public function __construct(
			string $legacyPath = 'legacy/',
			bool $preprocessingEnabled = true,
			array $excludedPaths = [],
			array $resolverClasses = [DefaultFileResolver::class],
			?ContainerInterface $container = null
		) {
			// Store the legacy path
			$this->legacyPath = $legacyPath;

			// Store the container used to autowire resolver dependencies
			$this->container = $container;

			// Store preprocessing setting
			$this->preprocessingEnabled = $preprocessingEnabled;

			// Set cache directory using kernel's project root
			$this->cacheDir = ComposerUtils::getProjectRoot() . '/storage/cache/legacy';

			// Create cache directory if preprocessing is enabled
			if ($this->preprocessingEnabled && !is_dir($this->cacheDir)) {
				mkdir($this->cacheDir, 0755, true);
			}

			// Initialize the recursive legacy preprocessor
			if ($this->preprocessingEnabled) {
				$this->preprocessor = new RecursiveLegacyPreprocessor($this->cacheDir, $this->legacyPath, $excludedPaths);
			}

			// Instantiate and register each configured resolver, in order
			foreach ($resolverClasses as $resolverClass) {
				$this->resolvers[] = $this->instantiateResolver($resolverClass);
			}
		}

		/**
		 * Instantiate a resolver class, passing $legacyPath as the 'legacyPath'
		 * constructor argument. When a container is available, any other
		 * constructor parameter is autowired the same way Canvas autowires
		 * controllers and aspects; without one, $legacyPath must be the only
		 * constructor argument.
		 * @param string $resolverClass Fully qualified class name of a FileResolverInterface implementation
		 * @return FileResolverInterface The instantiated resolver
		 */
		private function instantiateResolver(string $resolverClass): FileResolverInterface {
			if (!class_exists($resolverClass)) {
				throw new \InvalidArgumentException("Legacy resolver class '{$resolverClass}' does not exist.");
			}

			if ($this->container !== null) {
				$resolver = $this->container->make($resolverClass, ['legacyPath' => $this->legacyPath]);
			} else {
				$resolver = new $resolverClass($this->legacyPath);
			}

			if (!$resolver instanceof FileResolverInterface) {
				throw new \InvalidArgumentException("Legacy resolver class '{$resolverClass}' must implement " . FileResolverInterface::class . ".");
			}

			return $resolver;
		}
		
		/**
		 * Handle the request by attempting to find and execute a legacy file.
		 * Tries each resolver in order until one finds a matching file.
		 * @param Request $request The HTTP request to handle
		 * @return Response The response from executing the legacy file
		 * @throws RouteNotFoundException When no resolver can find a matching file
		 * @throws \Exception
		 */
		public function handle(Request $request): Response {
			// Fetch the path to resolve
			$path = $request->getPathInfo();
			
			// Try each resolver until one finds a file
			foreach ($this->resolvers as $resolver) {
				$legacyFile = $resolver->resolve($path, $request);
				
				// If resolver found a file and it passes security checks
				if ($legacyFile && $this->isSafeFile($legacyFile)) {
					return $this->executeLegacyFile($legacyFile, $request);
				}
			}
			
			// No resolver could handle this path
			throw new RouteNotFoundException("No route found");
		}
		
		/**
		 * Clear the legacy file preprocessing cache.
		 * @return int Number of files removed
		 */
		public function clearCache(): int {
			// Skip cleanup when preprocessing is disabled
			// or the cache directory does not exist.
			if (!$this->preprocessingEnabled || !is_dir($this->cacheDir)) {
				return 0;
			}
			
			// Collect all cached PHP preprocessing files.
			$files = glob($this->cacheDir . '/*.php');
			
			// glob() returns false on filesystem errors.
			if ($files === false) {
				return 0;
			}
			
			// Track how many files were successfully deleted.
			$removed = 0;
			
			foreach ($files as $file) {
				// Only count files that were actually removed.
				if (unlink($file)) {
					++$removed;
				}
			}
			
			return $removed;
		}

		/**
		 * Perform basic security checks on the resolved file, including a
		 * canonical-path check that blocks path traversal outside legacyPath.
		 * @param string $file Path to the file to check
		 * @return bool True if the file is safe to execute
		 */
		private function isSafeFile(string $file): bool {
			// Basic security: must be .php and exist
			if (!file_exists($file) || !is_readable($file) || !str_ends_with($file, '.php')) {
				return false;
			}

			// Canonicalize both paths and ensure the resolved file stays within legacyPath
			$realFile = realpath($file);
			$realLegacyPath = realpath($this->legacyPath);

			if ($realFile === false || $realLegacyPath === false) {
				return false;
			}

			return str_starts_with($realFile, $realLegacyPath . DIRECTORY_SEPARATOR);
		}
		
		/**
		 * Execute the legacy PHP file and capture its output.
		 * Sets up the execution environment and returns the output as a Response.
		 * @param string $file Path to the legacy file to execute
		 * @param Request $request The original HTTP request
		 * @return Response The response containing the legacy file's output
		 * @throws \Exception
		 */
		private function executeLegacyFile(string $file, Request $request): Response {
			// Reset per-request state. LegacyHelper.php only initializes $__canvas_headers
			// once per process (require_once); under a persistent worker (e.g. Swoole) that
			// process serves many requests, so without this reset one request's headers
			// (Location, Status, ...) could leak into the next request's response.
			global $__canvas_headers;
			$__canvas_headers = [];

			// Set up basic environment variables for legacy compatibility
			$this->setupGlobals($request);
			
			// Store the current working directory before we change it
			// This might be the project root or wherever the process started
			$previousWorkingDir = getcwd();
			
			// Validate that we got a directory
			if ($previousWorkingDir === false) {
				throw new \RuntimeException('Failed to get current working directory.');
			}
			
			// Determine which file to execute (original or preprocessed)
			if ($this->preprocessingEnabled) {
				$fileToExecute = $this->preprocessor->processFileRecursively($file);
			} else {
				$fileToExecute = $file;
			}
			
			// Capture output buffer to get the legacy file's output
			ob_start();
			
			try {
				// Set working directory
				chdir($this->legacyPath);
				
				// Include the file (original or preprocessed)
				include $fileToExecute;
				
				// Fetch the contents
				$content = ob_get_clean();
				
				// ob_get_clean can return false
				if ($content === false) {
					$content = '';
				}
				
				// Restore the previous working directory
				chdir($previousWorkingDir);
				
				// Create response with proper status and headers if preprocessing enabled
				return $this->preprocessingEnabled ? $this->createResponseWithHeaders($content) : new Response($content);
			} catch (LegacyExitException $e) {
				// Legacy code called exit() - get content up to that point
				$content = ob_get_clean();
				
				// ob_get_clean can return false
				if ($content === false) {
					$content = '';
				}
				
				// Restore the previous working directory
				chdir($previousWorkingDir);
				
				// Return response with statusCode and headers
				return $this->createResponseWithHeaders($content, $e->getExitCode());
			} catch (\Exception $e) {
				// Ensure we always restore the previous working directory
				chdir($previousWorkingDir);
				throw $e;
			}
		}
		
		/**
		 * Set up global variables that legacy PHP files expect.
		 * Populates $_GET, $_POST, $_REQUEST and starts session if needed.
		 * @param Request $request The HTTP request to extract data from
		 * @return void
		 */
		private function setupGlobals(Request $request): void {
			// Basic $_GET, $_POST setup for legacy compatibility
			$_GET = $request->query->all();
			$_POST = $request->request->all();
			$_REQUEST = array_merge($_GET, $_POST);
			
			// Start session if needed (legacy files often expect sessions)
			if (session_status() === PHP_SESSION_NONE) {
				session_start();
			}
		}
		
		/**
		 * Determine HTTP status code from parsed headers and exit code.
		 * @param array<string, string|int> $parsedHeaders Associative array of parsed headers
		 * @param int $exitCode Exit code from the legacy script
		 * @return int HTTP status code
		 */
		private function determineStatusCode(array $parsedHeaders, int $exitCode): int {
			// Check if a status header was explicitly set
			if (isset($parsedHeaders['Status'])) {
				$statusCode = (int)$parsedHeaders['Status'];
				
				if ($statusCode > 0) {
					return $statusCode;
				}
			}
			
			// No explicit status - use defaults based on context
			if (isset($parsedHeaders['Location'])) {
				return 302; // Default redirect status
			}
			
			// Regular response based on exit code
			return match ($exitCode) {
				0 => 200,
				1 => 500,
				default => $exitCode,
			};
		}
		
		/**
		 * Parse raw header strings into an associative array.
		 * @param array<string> $rawHeaders Array of raw header strings
		 * @return array<string, string|int> Associative array of headers
		 */
		private function parseHeaders(array $rawHeaders): array {
			$headers = [];
			
			foreach ($rawHeaders as $header) {
				// Extract status code from HTTP status lines
				if (preg_match('/^HTTP\/\d\.\d\s+(\d{3})/', $header, $matches)) {
					$headers['Status'] = (int)$matches[1];
					continue;
				}
				
				// Parse header: value format
				if (preg_match('/^([^:]+):\s*(.+)$/', $header, $matches)) {
					$headers[trim($matches[1])] = trim($matches[2]);
				}
			}
			
			return $headers;
		}
		
		/**
		 * Create a Response object with proper status code and headers from Canvas globals.
		 * @param string $content The output content from the legacy file
		 * @param int $exitCode The exit code (default: 0 for normal execution)
		 * @return Response The response with proper status and headers
		 */
		private function createResponseWithHeaders(string $content, int $exitCode = 0): Response {
			global $__canvas_headers;
			
			// Fetch and parse headers
			$rawHeaders = $__canvas_headers ?? [];
			$parsedHeaders = $this->parseHeaders($rawHeaders);
			
			// Determine the status code
			$statusCode = $this->determineStatusCode($parsedHeaders, $exitCode);

			// Create redirect response if needed
			if (isset($parsedHeaders['Location']) && is_string($parsedHeaders['Location']) && in_array($statusCode, [301, 302, 303, 307, 308])) {
				return new RedirectResponse($parsedHeaders['Location'], $statusCode, $rawHeaders);
			}
			
			// Return response
			return new Response($content, $statusCode, $rawHeaders);
		}
	}