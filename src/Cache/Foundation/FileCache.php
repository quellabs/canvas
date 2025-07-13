<?php
	
	namespace Quellabs\Canvas\Cache\Foundation;
	
	use Quellabs\Canvas\Cache\Contracts\CacheInterface;
	use Quellabs\Discover\Discover;
	
	/**
	 * File-based cache implementation with comprehensive concurrency protection
	 *
	 * This implementation provides thread-safe caching using file-based storage with:
	 * - Atomic file operations to prevent data corruption
	 * - Proper file locking to handle concurrent access
	 * - Process-level locking for expensive operations
	 * - Safe directory operations with race condition handling
	 */
	class FileCache implements CacheInterface {
		
		/** @var string Base cache directory */
		private string $cachePath;
		
		/** @var string Cache context for namespacing */
		private string $namespace;
		
		/** @var int Maximum time to wait for locks (seconds) */
		private int $lockTimeout;
		
		/** @var Discover */
		private Discover $discover;
		
		/**
		 * FileCache Constructor
		 * @param string $namespace Cache context for namespacing (e.g., 'pages', 'data')
		 * @param int $lockTimeout Maximum time to wait for locks in seconds
		 */
		public function __construct(string $namespace = 'default', int $lockTimeout = 5) {
			$this->discover = new Discover();
			$this->cachePath = rtrim($this->discover->getProjectRoot() . DIRECTORY_SEPARATOR . "storage" . DIRECTORY_SEPARATOR . "cache");
			$this->namespace = $namespace;
			$this->lockTimeout = $lockTimeout;
			
			// Ensure cache directory exists at construction time
			// This prevents directory creation race conditions later
			$this->ensureDirectoryExists();
		}
		
		/**
		 * Get an item from the cache
		 * @param string $key Cache key
		 * @param mixed $default Default value if key doesn't exist
		 * @return mixed The cached value or default
		 */
		public function get(string $key, mixed $default = null): mixed {
			$filePath = $this->getFilePath($key);
			
			// Read with proper locking to prevent reading corrupted data
			$data = $this->readCacheFileWithLock($filePath);
			
			// Handle cache miss or expired data
			if ($data === null || $this->isExpired($data)) {
				// Only attempt to delete if we found expired data
				// This prevents unnecessary file system operations
				if ($data !== null) {
					$this->forget($key);
				}
				
				return $default;
			}
			
			return $data['value'];
		}
		
		/**
		 * Store an item in the cache
		 * @param string $key Cache key
		 * @param mixed $value Value to cache
		 * @param int $ttl Time to live in seconds (0 = forever)
		 * @return bool True on success
		 */
		public function set(string $key, mixed $value, int $ttl = 3600): bool {
			// Fetches the file path
			$filePath = $this->getFilePath($key);
			
			// Ensure the directory exists before writing
			$this->ensureDirectoryExists($this->getContextPath());
			
			// Prepare cache data structure
			$data = [
				'value'      => $value,
				'expires_at' => $ttl > 0 ? time() + $ttl : 0, // 0 means never expires
				'created_at' => time()
			];
			
			// Use atomic write operation to prevent corruption
			return $this->writeFileAtomically($filePath, serialize($data));
		}
		
		/**
		 * Get an item or execute callback and store result
		 *
		 * This method implements the "cache-aside" pattern with proper
		 * concurrency control. It prevents multiple processes from
		 * executing expensive callbacks simultaneously for the same key.
		 *
		 * Process:
		 * 1. Check cache (fast path)
		 * 2. Acquire process lock if cache miss
		 * 3. Double-check cache after lock acquisition
		 * 4. Execute callback and store result if still missing
		 *
		 * @param string $key Cache key
		 * @param int $ttl Time to live in seconds
		 * @param callable $callback Callback to execute if cache miss
		 * @return mixed The cached or computed value
		 */
		public function remember(string $key, int $ttl, callable $callback): mixed {
			// Fast path: check cache first without locking
			$value = $this->get($key);
			
			// If found, return the value
			if ($value !== null) {
				return $value;
			}
			
			// Slow path: acquire lock to prevent multiple callback executions
			$lockPath = $this->getLockFilePath($key);
			$lockHandle = $this->acquireLock($lockPath);
			
			// If we can't acquire the lock, another process is likely
			// executing the callback. Check cache again and fall back
			// to executing the callback if still empty.
			if ($lockHandle === false) {
				$value = $this->get($key);
				return $value !== null ? $value : $callback();
			}
			
			try {
				// Double-check cache after acquiring lock
				// Another process might have filled it while we waited
				$value = $this->get($key);
				
				if ($value !== null) {
					return $value;
				}
				
				// Execute callback and store result
				$value = $callback();
				$this->set($key, $value, $ttl);
				
				return $value;
			} finally {
				// Always release the lock, even if callback throws exception
				$this->releaseLock($lockHandle, $lockPath);
			}
		}
		
		/**
		 * Remove an item from the cache
		 * @param string $key Cache key
		 * @return bool True if item was removed or didn't exist
		 */
		public function forget(string $key): bool {
			$filePath = $this->getFilePath($key);
			return $this->deleteFileSafely($filePath);
		}
		
		/**
		 * Clear all items from the cache context
		 * @return bool True on success
		 */
		public function flush(): bool {
			// Fetches context path
			$contextPath = $this->getContextPath();
			
			// Nothing to flush if directory doesn't exist
			if (!is_dir($contextPath)) {
				return true;
			}
			
			return $this->deleteDirectory($contextPath);
		}
		
		/**
		 * Check if an item exists in the cache
		 * @param string $key Cache key
		 * @return bool True if key exists and hasn't expired
		 */
		public function has(string $key): bool {
			return $this->get($key) !== null;
		}
		
		/**
		 * Get the full file path for a cache key
		 * @param string $key Cache key
		 * @return string Full file path
		 */
		private function getFilePath(string $key): string {
			$hashedKey = $this->hashKey($key);
			return $this->getContextPath() . '/' . $hashedKey . '.cache';
		}
		
		/**
		 * Get the lock file path for a cache key
		 * Places lock file next to cache file with .lock extension
		 * @param string $key Cache key
		 * @return string Lock file path
		 */
		private function getLockFilePath(string $key): string {
			$hashedKey = $this->hashKey($key);
			return $this->getContextPath() . '/' . $hashedKey . '.lock';
		}
		
		/**
		 * Get the context directory path
		 * @return string Context directory path
		 */
		private function getContextPath(): string {
			return $this->cachePath . '/' . $this->namespace;
		}
		
		/**
		 * Hash a cache key for safe file naming
		 *
		 * Uses SHA-256 to create filesystem-safe filenames from arbitrary
		 * cache keys. This handles keys with special characters, spaces,
		 * or extreme lengths that would cause filesystem issues.
		 *
		 * @param string $key Cache key
		 * @return string Hashed key (64 characters)
		 */
		private function hashKey(string $key): string {
			return hash('sha256', $key);
		}
		
		/**
		 * Read and unserialize a cache file with proper locking
		 *
		 * This method implements safe file reading with shared locks
		 * to prevent reading corrupted data during concurrent writes.
		 *
		 * Process:
		 * 1. Check file existence (fast fail)
		 * 2. Open file for reading
		 * 3. Acquire shared lock with timeout
		 * 4. Read and validate file contents
		 * 5. Unserialize and validate data structure
		 *
		 * @param string $filePath File path
		 * @return array|null Cache data or null if invalid/not found
		 */
		private function readCacheFileWithLock(string $filePath): ?array {
			// Fast path: check if file exists before opening
			if (!file_exists($filePath)) {
				return null;
			}
			
			// Open file for reading
			$handle = @fopen($filePath, 'r');
			if ($handle === false) {
				return null;
			}
			
			try {
				// Acquire shared lock to prevent reading during writes
				// Multiple readers can hold shared locks simultaneously
				if (!$this->acquireFileLock($handle, LOCK_SH)) {
					return null;
				}
				
				// Get file size for efficient reading
				$fileSize = filesize($filePath);
				
				if ($fileSize === false || $fileSize === 0) {
					return null;
				}
				
				// Read entire file content
				$contents = fread($handle, $fileSize);
				
				if ($contents === false) {
					return null;
				}
				
				// Attempt to unserialize the data
				$data = @unserialize($contents);
				
				// Validate data structure
				if (!is_array($data) || !isset($data['value'], $data['expires_at'], $data['created_at'])) {
					return null;
				}
				
				return $data;
			} finally {
				// Always release lock and close file handle
				flock($handle, LOCK_UN);
				fclose($handle);
			}
		}
		
		/**
		 * This method implements atomic file writing to prevent data corruption
		 * during concurrent operations. The process does this:
		 *
		 * 1. Write to a temporary file with exclusive lock
		 * 2. Atomically rename it to final destination
		 * 3. Clean up the temporary file on failure
		 *
		 * The rename operation is atomic on most filesystems, meaning
		 * readers will either see the old file or the new file, never
		 * a partially written file.
		 *
		 * @param string $filePath Target file path
		 * @param string $data Data to write
		 * @return bool True on success
		 */
		private function writeFileAtomically(string $filePath, string $data): bool {
			// Create unique temporary file name
			// Include PID and random number to prevent collisions
			$tempPath = $filePath . '.tmp.' . getmypid() . '.' . mt_rand();
			
			// Write to the temporary file with exclusive lock
			// LOCK_EX prevents other processes from writing simultaneously
			$result = file_put_contents($tempPath, $data, LOCK_EX);
			
			if ($result === false) {
				// Clean up the temporary file if write failed
				@unlink($tempPath);
				return false;
			}
			
			// Atomically move the temporary file to the final destination
			// This operation is atomic on most filesystems
			if (rename($tempPath, $filePath)) {
				return true;
			}
			
			// Clean up the temporary file if rename failed
			@unlink($tempPath);
			return false;
		}
		
		/**
		 * This method implements non-blocking lock acquisition with timeout
		 * to prevent indefinite blocking. It repeatedly attempts to acquire
		 * the lock with short sleep intervals.
		 * @param resource $handle File handle
		 * @param int $operation Lock operation (LOCK_SH or LOCK_EX)
		 * @return bool True if lock acquired within timeout
		 */
		private function acquireFileLock($handle, int $operation): bool {
			$startTime = microtime(true);
			
			// Keep trying until timeout is reached
			while (microtime(true) - $startTime < $this->lockTimeout) {
				// Try to acquire lock non-blocking
				if (flock($handle, $operation | LOCK_NB)) {
					return true;
				}
				
				// Sleep briefly before retrying (10ms)
				// This prevents busy-waiting and reduces CPU usage
				usleep(10000);
			}
			
			return false;
		}
		
		/**
		 * This method creates a lock file that coordinates access between
		 * different processes. It's used primarily in the remember() method
		 * to prevent multiple processes from executing expensive callbacks.
		 * @param string $lockPath Lock file path
		 * @return resource|false Lock handle or false on failure
		 */
		private function acquireLock(string $lockPath) {
			// Ensure lock directory exists
			$this->ensureDirectoryExists($this->getContextPath());
			
			// Create/open lock file
			$handle = @fopen($lockPath, 'w');
			
			if ($handle === false) {
				return false;
			}
			
			// Try to acquire exclusive lock
			if ($this->acquireFileLock($handle, LOCK_EX)) {
				return $handle;
			}
			
			// Close handle if lock acquisition failed
			fclose($handle);
			return false;
		}
		
		/**
		 * This method releases the lock and removes the lock file.
		 * It's important to clean up lock files to prevent accumulation
		 * of stale lock files in the filesystem.
		 * @param resource $handle Lock handle
		 * @param string $lockPath Lock file path
		 */
		private function releaseLock($handle, string $lockPath): void {
			// Release lock and close handle
			if (is_resource($handle)) {
				flock($handle, LOCK_UN);
				fclose($handle);
			}
			
			// Remove lock file
			// Use @ to suppress warnings if file was already removed
			@unlink($lockPath);
		}
		
		/**
		 * Delete a file safely (handles concurrent deletion)
		 * @param string $filePath File path to delete
		 * @return bool True if file was deleted or didn't exist
		 */
		private function deleteFileSafely(string $filePath): bool {
			// Use @ to suppress warnings for concurrent deletions
			// Check file existence after deletion attempt to handle race conditions
			return @unlink($filePath) || !file_exists($filePath);
		}
		
		/**
		 * Check if cached data has expired
		 * @param array $data Cache data
		 * @return bool True if expired
		 */
		private function isExpired(array $data): bool {
			// Never expires if expires_at is 0
			if ($data['expires_at'] === 0) {
				return false;
			}
			
			// Check if current time exceeds expiration time
			return time() > $data['expires_at'];
		}
		
		/**
		 * Ensure directory exists with proper error handling
		 * @param string|null $path Directory path (uses context path if null)
		 * @throws \RuntimeException If directory creation fails
		 */
		private function ensureDirectoryExists(?string $path = null): void {
			$path = $path ?? $this->getContextPath();
			
			// Check if directory already exists
			if (!is_dir($path)) {
				// Use @ to suppress warnings for concurrent directory creation
				// The recursive flag (true) creates parent directories as needed
				@mkdir($path, 0755, true);
				
				// Double-check in case another process created it
				// or if mkdir() failed silently
				if (!is_dir($path)) {
					throw new \RuntimeException("Could not create cache directory: {$path}");
				}
			}
		}
		
		/**
		 * Recursively delete a directory
		 * @param string $path Directory path
		 * @return bool True on success
		 */
		private function deleteDirectory(string $path): bool {
			// Nothing to delete if directory doesn't exist
			if (!is_dir($path)) {
				return true;
			}
			
			// Get directory contents
			$files = @scandir($path);
			
			if ($files === false) {
				return false;
			}
			
			// Filter out . and .. entries
			$files = array_diff($files, ['.', '..']);
			
			// Delete each file and subdirectory
			foreach ($files as $file) {
				$filePath = $path . '/' . $file;
				
				if (is_dir($filePath)) {
					// Recursively delete subdirectory
					if (!$this->deleteDirectory($filePath)) {
						return false;
					}
				} else {
					// Delete file safely
					if (!$this->deleteFileSafely($filePath)) {
						return false;
					}
				}
			}
			
			// Remove the now-empty directory
			// Use @ to suppress warnings from concurrent operations
			return @rmdir($path);
		}
	}