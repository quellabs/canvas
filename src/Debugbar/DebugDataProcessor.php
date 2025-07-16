<?php
	
	namespace Quellabs\Canvas\Debugbar;
	
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\File\UploadedFile;
	
	class DebugDataProcessor {
		
		private DebugEventCollector $collector;
		
		/**
		 * DebugDataProcessor constructor
		 * @param DebugEventCollector $collector
		 */
		public function __construct(DebugEventCollector $collector) {
			$this->collector = $collector;
		}
		
		/**
		 * Get all processed debug data for the request
		 */
		public function getDebugData(Request $request): array {
			return [
				'stats'   => $this->getStats(),
				'cache'   => $this->getCacheData(),
				'aspects' => $this->getAspectsData(),
				'queries' => $this->getQueriesData(),
				'route'   => $this->getRouteData(),
				'request' => $this->getRequestData($request),
			];
		}
		
		/**
		 * Get performance statistics
		 */
		private function getStats(): array {
			$stats = ['time' => 0, 'memory' => 0, 'queryTime' => 0];
			
			foreach ($this->collector->getEvents() as $event) {
				switch ($event['signal']) {
					case 'debug.canvas.query':
						$stats['time'] += $event['data']['execution_time_ms'] ?? 0;
						$stats['memory'] += $event['data']['memory_used_bytes'] ?? 0;
						break;
					
					case 'debug.objectquel.query':
						$stats['queryTime'] += $event['data']['execution_time_ms'] ?? 0;
						break;
				}
			}
			
			return $stats;
		}
		
		/**
		 * Get cache-related data
		 */
		private function getCacheData(): array {
			$cacheData = [];
			
			foreach ($this->collector->getEvents() as $event) {
				if ($event['signal'] === 'debug.cache') {
					$cacheData[] = $event['data'];
				}
			}
			
			return $cacheData;
		}
		
		/**
		 * Get aspects data
		 */
		private function getAspectsData(): array {
			$aspectsData = [];
			
			foreach ($this->collector->getEvents() as $event) {
				if ($event['signal'] === 'debug.aspect') {
					$aspectsData[] = $event['data'];
				}
			}
			
			return $aspectsData;
		}
		
		/**
		 * Get database queries data
		 */
		private function getQueriesData(): array {
			$queries = [];
			
			foreach ($this->collector->getEvents() as $event) {
				if ($event['signal'] === 'debug.objectquel.query') {
					$queries[] = $event['data'];
				}
			}
			
			return $queries;
		}
		
		/**
		 * Get route information
		 */
		private function getRouteData(): array {
			foreach ($this->collector->getEvents() as $event) {
				if ($event['signal'] === 'debug.canvas.query') {
					return array_merge($event['data'], ['legacyFile' => '']);
				}
			}
			
			return [];
		}
		
		/**
		 * Get request data
		 */
		private function getRequestData(Request $request): array {
			return [
				'method'    => $request->getMethod(),
				'uri'       => $request->getRequestUri(),
				'url'       => $request->getUri(),
				'ip'        => $request->getClientIp(),
				'userAgent' => $request->headers->get('User-Agent', ''),
				'referer'   => $request->headers->get('Referer'),
				'headers'   => $this->getFilteredHeaders($request),
				'query'     => $request->query->all(),
				'request'   => $request->request->all(),
				'files'     => $this->getFileData($request),
				'cookies'   => $request->cookies->all(),
				'session'   => $request->hasSession() ? $this->getFilteredSession($request) : [],
			];
		}
		
		/**
		 * Get filtered session data (excluding sensitive information)
		 */
		private function getFilteredSession(Request $request): array {
			if (!$request->hasSession()) {
				return [];
			}
			
			$sessionData = $request->getSession()->all();
			
			// Simple list of keys to exclude
			$excludeKeys = [
				'password', 'token', 'csrf', 'secret', 'key', 'auth'
			];
			
			$filtered = [];
			
			foreach ($sessionData as $key => $value) {
				// Skip if key contains sensitive words
				$skip = false;
				foreach ($excludeKeys as $excludeKey) {
					if (stripos($key, $excludeKey) !== false) {
						$skip = true;
						break;
					}
				}
				
				if (!$skip) {
					// Limit string length and don't show objects
					if (is_string($value) && strlen($value) > 100) {
						$filtered[$key] = substr($value, 0, 100) . '...';
					} elseif (is_array($value) || is_scalar($value)) {
						$filtered[$key] = $value;
					} else {
						$filtered[$key] = '[object]';
					}
				}
			}
			
			return $filtered;
		}
		
		/**
		 * Get filtered headers (excluding sensitive information)
		 */
		private function getFilteredHeaders(Request $request): array {
			$headers = $request->headers->all();
			
			// Headers to exclude for security/privacy reasons
			$sensitiveHeaders = [
				'authorization',
				'cookie',
				'x-api-key',
				'x-auth-token',
				'x-access-token',
				'bearer',
				'php-auth-user',
				'php-auth-pw',
				'php-auth-digest',
				'www-authenticate',
				'proxy-authorization',
				'x-forwarded-authorization',
			];
			
			// Headers that can contain sensitive data in values
			$headerPatternsToFilter = [
				'/^x-.*-key$/i',
				'/^x-.*-token$/i',
				'/^x-.*-secret$/i',
				'/.*-auth.*/i',
			];
			
			$filtered = [];
			
			foreach ($headers as $name => $values) {
				$lowerName = strtolower($name);
				
				// Skip explicitly sensitive headers
				if (in_array($lowerName, $sensitiveHeaders)) {
					continue;
				}
				
				// Skip headers matching sensitive patterns
				$skipHeader = false;
				foreach ($headerPatternsToFilter as $pattern) {
					if (preg_match($pattern, $lowerName)) {
						$skipHeader = true;
						break;
					}
				}
				
				if ($skipHeader) {
					continue;
				}
				
				// Symfony headers are arrays, but we usually want the first value
				// Some headers like Accept might have multiple values, so we join them
				if (is_array($values)) {
					if (count($values) === 1) {
						$filtered[$name] = $values[0];
					} else {
						$filtered[$name] = implode(', ', $values);
					}
				} else {
					$filtered[$name] = $values;
				}
			}
			
			return $filtered;
		}
		
		/**
		 * Get uploaded file data
		 */
		private function getFileData(Request $request): array {
			$files = [];
			
			// Get all uploaded files from the request
			$uploadedFiles = $request->files->all();
			
			// Process files recursively (handles nested file inputs)
			$this->processFileInputs($uploadedFiles, $files);
			
			return $files;
		}
		
		/**
		 * Process file inputs recursively
		 */
		private function processFileInputs($fileInputs, array &$files, string $prefix = ''): void {
			foreach ($fileInputs as $name => $file) {
				$fullName = $prefix ? $prefix . '[' . $name . ']' : $name;
				
				if (is_array($file)) {
					// Handle array of files (e.g., multiple file uploads)
					$this->processFileInputs($file, $files, $fullName);
				} elseif ($file instanceof UploadedFile) {
					// Process single uploaded file
					$files[$fullName] = $this->extractFileInfo($file);
				}
			}
		}
		
		/**
		 * Extract file information from uploaded file
		 */
		private function extractFileInfo(UploadedFile $file): array {
			return [
				'originalName'  => $file->getClientOriginalName(),
				'mimeType'      => $file->getClientMimeType(),
				'size'          => $file->getSize(),
				'sizeFormatted' => $this->formatFileSize($file->getSize()),
				'error'         => $file->getError(),
				'errorMessage'  => $this->getUploadErrorMessage($file->getError()),
				'isValid'       => $file->isValid(),
				'extension'     => $file->getClientOriginalExtension(),
				'tempPath'      => $file->getRealPath(),
			];
		}
		
		/**
		 * Format file size in human-readable format
		 */
		private function formatFileSize(?int $bytes): string {
			if ($bytes === null || $bytes === 0) {
				return '0 B';
			}
			
			$units = ['B', 'KB', 'MB', 'GB', 'TB'];
			$power = floor(log($bytes, 1024));
			$power = min($power, count($units) - 1);
			
			$size = $bytes / pow(1024, $power);
			$formattedSize = round($size, 2);
			
			return $formattedSize . ' ' . $units[$power];
		}
		
		/**
		 * Get upload error message
		 */
		private function getUploadErrorMessage(int $error): string {
			return match ($error) {
				UPLOAD_ERR_OK => 'No error',
				UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize directive',
				UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE directive',
				UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
				UPLOAD_ERR_NO_FILE => 'No file was uploaded',
				UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
				UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
				UPLOAD_ERR_EXTENSION => 'Upload stopped by extension',
				default => 'Unknown upload error',
			};
		}
	}