<?php
	
	namespace Quellabs\Canvas\Legacy;
	
	use Quellabs\Canvas\Exceptions\RouteNotFoundException;
	use Quellabs\Canvas\Kernel;
	use Quellabs\Canvas\Legacy\LegacyExitException;
	use Quellabs\Canvas\Legacy\Resolvers\DefaultFileResolver;
	use Symfony\Component\HttpFoundation\RedirectResponse;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	/**
	 * Handles fallthrough routing for legacy PHP files when modern routes don't match.
	 * This allows gradual migration from legacy PHP files to modern framework routes.
	 */
	class LegacyHandler {
		
		/** @var FileResolverInterface[] Array of file resolvers to try in order */
		private array $resolvers = [];
		
		/** @var string Base path where legacy files are located */
		private string $legacyPath;
		
		/** @var bool True if we should preprocess the legacy php file */
		private bool $preprocessingEnabled;
		
		/** @var LegacyPreprocessor Optional preprocessor for handling exit() and headers */
		private LegacyPreprocessor $preprocessor;
		
		/**
		 * Cache directory for preprocessed legacy PHP files
		 * @var string
		 */
		private string $cacheDir;
		
		/**
		 * Initialize the handler with a base legacy path.
		 * @param Kernel $kernel
		 * @param string $legacyPath Base directory path for legacy files
		 * @param bool $preprocessingEnabled
		 */
		public function __construct(Kernel $kernel, string $legacyPath = 'legacy/', bool $preprocessingEnabled = true) {
			// Store the legacy path
			$this->legacyPath = $legacyPath;
			
			// Store preprocessing setting
			$this->preprocessingEnabled = $preprocessingEnabled;
			
			// Set cache directory using kernel's project root
			$this->cacheDir = $kernel->getDiscover()->getProjectRoot() . '/storage/cache/legacy';
			
			// Create cache directory if preprocessing is enabled
			if ($this->preprocessingEnabled && !is_dir($this->cacheDir)) {
				mkdir($this->cacheDir, 0755, true);
			}
			
			// Initialize the legacy preprocessor only if needed
			if ($this->preprocessingEnabled) {
				$this->preprocessor = new LegacyPreprocessor();
			}
			
			// Add default resolver for standard file resolution
			$this->addResolver(new DefaultFileResolver($this->legacyPath));
		}
		
		/**
		 * Add a file resolver to the chain of resolvers.
		 * Resolvers are tried in the order they were added.
		 * @param FileResolverInterface $resolver The resolver to add
		 * @return self Fluent interface
		 */
		public function addResolver(FileResolverInterface $resolver): self {
			$this->resolvers[] = $resolver;
			return $this;
		}
		
		/**
		 * Handle the request by attempting to find and execute a legacy file.
		 * Tries each resolver in order until one finds a matching file.
		 * @param Request $request The HTTP request to handle
		 * @return Response The response from executing the legacy file
		 * @throws RouteNotFoundException When no resolver can find a matching file
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
			throw RouteNotFoundException::forLegacyFallthrough($request->getPathInfo());
		}
		
		/**
		 * Clear the legacy file preprocessing cache.
		 * @return int Number of files removed
		 */
		public function clearCache(): int {
			if (!$this->preprocessingEnabled || !is_dir($this->cacheDir)) {
				return 0;
			}
			
			$files = glob($this->cacheDir . '/*.php');
			$removed = 0;
			
			foreach ($files as $file) {
				if (unlink($file)) {
					++$removed;
				}
			}
			
			return $removed;
		}
		
		/**
		 * Check if preprocessing is enabled.
		 * @return bool True if preprocessing is enabled
		 */
		public function isPreprocessingEnabled(): bool {
			return $this->preprocessingEnabled;
		}
		
		/**
		 * Perform basic security checks on the resolved file.
		 * Ensures the file exists, is readable, and has a .php extension.
		 * @param string $file Path to the file to check
		 * @return bool True if the file is safe to execute
		 */
		private function isSafeFile(string $file): bool {
			// Basic security: must be .php and exist
			return
				file_exists($file) &&
				str_ends_with($file, '.php') &&
				is_readable($file);
		}
		
		/**
		 * Get the preprocessed version of a legacy file, creating it if necessary.
		 * @param string $originalFile Path to the original legacy file
		 * @return string Path to the preprocessed file
		 */
		private function getProcessedFile(string $originalFile): string {
			// Generate a cache key based on file path and modification time
			$cacheKey = md5($originalFile . filemtime($originalFile));
			$cachedFile = $this->cacheDir . '/' . $cacheKey . basename($originalFile);
			
			// Create a preprocessed file if it doesn't exist
			if (!file_exists($cachedFile)) {
				$processedContent = $this->preprocessor->preprocess($originalFile);
				file_put_contents($cachedFile, $processedContent);
			}
			
			return $cachedFile;
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
			// Set up basic environment variables for legacy compatibility
			$this->setupGlobals($request);
			
			// Store the current working directory before we change it
			// This might be the project root or wherever the process started
			$previousWorkingDir = getcwd();
			
			// Determine which file to execute (original or preprocessed)
			if ($this->preprocessingEnabled) {
				$fileToExecute = $this->getProcessedFile($file);
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

				// Restore the previous working directory
				chdir($previousWorkingDir);
				
				// Create response with proper status and headers if preprocessing enabled
				return $this->preprocessingEnabled ? $this->createResponseWithHeaders($content) : new Response($content);
			} catch (LegacyExitException $e) {
				// Legacy code called exit() - get content up to that point
				$content = ob_get_clean();

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
		 * @param array $parsedHeaders Associative array of parsed headers
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
		 * @param array $rawHeaders Array of raw header strings
		 * @return array Associative array of headers
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
			if (isset($parsedHeaders['Location']) && in_array($statusCode, [301, 302, 303, 307, 308])) {
				return new RedirectResponse($parsedHeaders['Location'], $statusCode, $rawHeaders);
			}
			
			// Return response
			return new Response($content, $statusCode, $rawHeaders);
		}
	}