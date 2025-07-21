<?php
	
	namespace Quellabs\Canvas\Inspector\Helpers;
	
	use Symfony\Component\HttpFoundation\File\UploadedFile;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * This class safely extracts various components of an HTTP request while filtering
	 * out sensitive information such as authentication headers, passwords, and tokens.
	 * It's designed to be used in debug bars or logging systems where you need to
	 * inspect request data without exposing sensitive information.
	 */
	class RequestExtractor {
		
		/**
		 * The Symfony Request object to extract data from
		 */
		private Request $request;
		
		/**
		 * Constructor - Initialize the extractor with a request object
		 * @param Request $request The Symfony Request object to process
		 */
		public function __construct(Request $request) {
			$this->request = $request;
		}
		
		/**
		 * Main method to process and extract all relevant request data
		 *
		 * Returns a comprehensive array of request information including:
		 * - HTTP method and URI information
		 * - Client information (IP, User Agent)
		 * - Headers (filtered for security)
		 * - Query parameters, POST data, and uploaded files
		 * - Cookies and session data (filtered for security)
		 *
		 * @return array Complete request data array
		 */
		public function processRequestData(): array {
			return [
				'method'    => $this->request->getMethod(),              // HTTP method (GET, POST, etc.)
				'uri'       => $this->request->getRequestUri(),          // Request URI with query string
				'url'       => $this->request->getUri(),                 // Full URL including scheme and host
				'ip'        => $this->request->getClientIp(),            // Client IP address
				'userAgent' => $this->request->headers->get('User-Agent', ''), // Browser/client identifier
				'referer'   => $this->request->headers->get('Referer'),  // Referring page URL
				'headers'   => $this->getFilteredHeaders(),              // HTTP headers (security filtered)
				'query'     => $this->request->query->all(),             // GET parameters
				'request'   => $this->request->request->all(),           // POST parameters
				'files'     => $this->getFileData(),                     // Uploaded file information
				'cookies'   => $this->request->cookies->all(),           // Cookie values
				'session'   => $this->request->hasSession() ? $this->getFilteredSession() : [], // Session data (filtered)
			];
		}
		
		/**
		 * Filter HTTP headers to remove sensitive authentication and security information
		 *
		 * This method removes headers that commonly contain sensitive data such as:
		 * - Authorization headers (Bearer tokens, Basic auth, etc.)
		 * - API keys and access tokens
		 * - Authentication-related headers
		 *
		 * It uses both an explicit blacklist and pattern matching for comprehensive filtering.
		 *
		 * @return array Filtered headers safe for debugging/logging
		 */
		private function getFilteredHeaders(): array {
			// Get all headers from the current request
			$headers = $this->request->headers->all();
			
			// Explicit list of headers to exclude for security/privacy reasons
			// These are common header names that typically contain sensitive information
			$sensitiveHeaders = [
				'authorization',              // Standard HTTP auth header
				'cookie',                    // Session cookies and auth tokens
				'x-api-key',                 // API authentication keys
				'x-auth-token',              // Custom auth tokens
				'x-access-token',            // Access tokens
				'bearer',                    // Bearer token headers
				'php-auth-user',             // PHP basic auth username
				'php-auth-pw',               // PHP basic auth password
				'php-auth-digest',           // PHP digest authentication
				'www-authenticate',          // Server auth challenge
				'proxy-authorization',       // Proxy authentication
				'x-forwarded-authorization', // Forwarded auth headers
			];
			
			// Regular expression patterns to catch additional sensitive headers
			// This catches headers that follow common naming patterns for sensitive data
			$headerPatternsToFilter = [
				'/^x-.*-key$/i',      // Headers ending with '-key' (e.g., x-client-key)
				'/^x-.*-token$/i',    // Headers ending with '-token' (e.g., x-csrf-token)
				'/^x-.*-secret$/i',   // Headers ending with '-secret' (e.g., x-api-secret)
				'/.*-auth.*/i',       // Any header containing 'auth' (e.g., custom-auth-header)
			];
			
			// Initialize array to store filtered (safe) headers
			$filtered = [];
			
			// Process each header from the request
			foreach ($headers as $name => $values) {
				// Convert header name to lowercase for case-insensitive comparison
				$lowerName = strtolower($name);
				
				// Skip explicitly sensitive headers by checking against our blacklist
				if (in_array($lowerName, $sensitiveHeaders)) {
					continue; // Skip this header - it's on our sensitive list
				}
				
				// Skip headers matching sensitive patterns using regex
				$skipHeader = false;
				
				// Check each pattern to see if this header matches
				foreach ($headerPatternsToFilter as $pattern) {
					if (preg_match($pattern, $lowerName)) {
						$skipHeader = true; // Mark for skipping
						break; // No need to check remaining patterns
					}
				}
				
				// If header matched a sensitive pattern, skip it
				if ($skipHeader) {
					continue;
				}
				
				// Handle array values - convert to string for easier display
				// HTTP headers can have multiple values, so we need to handle both cases
				if (count($values) === 1) {
					$filtered[$name] = $values[0]; // Single value - use it directly
				} else {
					$filtered[$name] = implode(', ', $values); // Multiple values - join them with comma separator
				}
			}
			
			// Return the filtered headers array (safe for logging/debugging)
			return $filtered;
		}
		
		/**
		 * Extract and filter session data to remove sensitive information
		 *
		 * This method processes session data by:
		 * - Removing keys that contain sensitive words (password, token, etc.)
		 * - Truncating long string values to prevent memory issues
		 * - Handling different data types appropriately
		 *
		 * @return array Filtered session data safe for debugging
		 */
		private function getFilteredSession(): array {
			// Early return if no session exists
			if (!$this->request->hasSession()) {
				return [];
			}
			
			$sessionData = $this->request->getSession()->all();
			
			// Keys to exclude based on common sensitive data patterns
			$excludeKeys = ['password', 'token', 'csrf', 'secret', 'key', 'auth'];
			$filtered = [];
			
			foreach ($sessionData as $key => $value) {
				// Skip if key contains sensitive words (case-insensitive)
				$skip = false;
				foreach ($excludeKeys as $excludeKey) {
					if (stripos($key, $excludeKey) !== false) {
						$skip = true;
						break;
					}
				}
				
				if (!$skip) {
					// Handle different data types appropriately
					if (is_string($value) && strlen($value) > 100) {
						// Truncate long strings to prevent memory/display issues
						$filtered[$key] = substr($value, 0, 100) . '...';
					} elseif (is_array($value) || is_scalar($value)) {
						// Include arrays and scalar values as-is
						$filtered[$key] = $value;
					} else {
						// Replace objects with a placeholder to avoid serialization issues
						$filtered[$key] = '[object]';
					}
				}
			}
			
			return $filtered;
		}
		
		/**
		 * Extract information about uploaded files
		 * @return array Array of file information indexed by input name
		 */
		private function getFileData(): array {
			$files = [];
			$uploadedFiles = $this->request->files->all();
			$this->processFileInputs($uploadedFiles, $files);
			return $files;
		}
		
		/**
		 * Recursively process file inputs to handle nested file arrays
		 * @param array $fileInputs The file inputs to process (can be nested arrays)
		 * @param array &$files Reference to the array being built with file data
		 * @param string $prefix Current prefix for nested file names
		 */
		private function processFileInputs(array $fileInputs, array &$files, string $prefix = ''): void {
			foreach ($fileInputs as $name => $file) {
				// Build the full input name (handling nested structures like files[docs][pdf])
				$fullName = $prefix ? $prefix . '[' . $name . ']' : $name;
				
				if (is_array($file)) {
					// Recursively process nested file arrays
					$this->processFileInputs($file, $files, $fullName);
				} elseif ($file instanceof UploadedFile) {
					// Extract information from individual uploaded files
					$files[$fullName] = $this->extractFileInfo($file);
				}
			}
		}
		
		/**
		 * Extract detailed information from an uploaded file
		 *
		 * Creates a comprehensive array of file metadata including:
		 * - Original filename and MIME type
		 * - File size (raw and human-readable)
		 * - Upload status and error information
		 * - File extension and temporary path
		 *
		 * @param UploadedFile $file The uploaded file to analyze
		 * @return array Comprehensive file information
		 */
		private function extractFileInfo(UploadedFile $file): array {
			return [
				'originalName'  => $file->getClientOriginalName(),       // Original filename from client
				'mimeType'      => $file->getClientMimeType(),           // MIME type reported by client
				'size'          => $file->getSize(),                     // File size in bytes
				'sizeFormatted' => $this->formatFileSize($file->getSize()), // Human-readable size
				'error'         => $file->getError(),                    // Upload error code
				'errorMessage'  => $this->getUploadErrorMessage($file->getError()), // Human-readable error
				'isValid'       => $file->isValid(),                     // Whether upload was successful
				'extension'     => $file->getClientOriginalExtension(),  // File extension
				'tempPath'      => $file->getRealPath(),                 // Temporary file path on server
			];
		}
		
		/**
		 * Format file size in human-readable format
		 * @param int|null $bytes File size in bytes
		 * @return string Formatted file size (e.g., "1.5 MB")
		 */
		private function formatFileSize(?int $bytes): string {
			// Handle null or zero bytes
			if ($bytes === null || $bytes === 0) {
				return '0 B';
			}
			
			// Define size units
			$units = ['B', 'KB', 'MB', 'GB', 'TB'];
			
			// Calculate the appropriate unit (log base 1024)
			$power = floor(log($bytes, 1024));
			$power = min($power, count($units) - 1); // Don't exceed available units
			
			// Convert to the appropriate unit and round to 2 decimal places
			$size = $bytes / pow(1024, $power);
			return round($size, 2) . ' ' . $units[$power];
		}
		
		/**
		 * Get a human-readable error message for file upload errors
		 * @param int $error PHP upload error constant
		 * @return string Human-readable error description
		 */
		private function getUploadErrorMessage(int $error): string {
			return match ($error) {
				UPLOAD_ERR_OK => 'No error',                                          // Successful upload
				UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize directive',  // Too large (php.ini)
				UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE directive',       // Too large (form)
				UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',             // Incomplete upload
				UPLOAD_ERR_NO_FILE => 'No file was uploaded',                         // Empty file input
				UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',                  // Server config issue
				UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',              // Permissions issue
				UPLOAD_ERR_EXTENSION => 'Upload stopped by extension',                // Blocked by extension
				default => 'Unknown upload error',                                    // Unrecognized error
			};
		}
	}