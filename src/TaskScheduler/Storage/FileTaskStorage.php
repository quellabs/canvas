<?php
	
	namespace Quellabs\Canvas\TaskScheduler\Storage;
	
	use DateTime;
	use RuntimeException;
	
	class FileTaskStorage implements TaskStorageInterface {
		
		private string $storageDirectory;
		private int $lockTimeout;
		private int $maxLockWaitTime;
		
		// Track acquired locks to ensure proper ownership
		private array $acquiredLocks = [];
		
		// Exponential backoff constants
		private const int INITIAL_BACKOFF_MS = 10;     // Start with 10ms
		private const int MAX_BACKOFF_MS = 1000;       // Cap at 1 second
		private const int BACKOFF_MULTIPLIER = 2;      // Double each time
		private const float JITTER_FACTOR = 0.1;       // Add ±10% jitter
		
		/**
		 * FileTaskStorage constructor
		 * @param string|null $storageDirectory
		 * @param int $lockTimeout
		 * @param int $maxLockWaitTime
		 */
		public function __construct(
			?string $storageDirectory = null,
			int     $lockTimeout = 30,
			int     $maxLockWaitTime = 10
		) {
			$this->storageDirectory = $storageDirectory ?? sys_get_temp_dir() . '/task_scheduler';
			$this->lockTimeout = $lockTimeout;
			$this->maxLockWaitTime = $maxLockWaitTime;
			
			// Ensure the storage directory exists
			$this->ensureStorage();
		}
		
		/**
		 * Clean up any locks we're tracking when the object is destroyed
		 * This helps prevent orphaned locks if the process terminates unexpectedly
		 */
		public function __destruct() {
			// Iterate through all locks currently held by this instance
			foreach (array_keys($this->acquiredLocks) as $lockFile) {
				// Release each lock to prevent orphaned lock files
				// This is a safety mechanism for unexpected process termination
				$this->releaseLock($lockFile);
			}
			
			// Note: This destructor provides best-effort cleanup but cannot guarantee
			// lock release in cases of abrupt process termination (SIGKILL, crashes, etc.)
		}

		/**
		 * Marks the task as busy
		 * @param string $taskName
		 * @param DateTime $dateTime
		 * @return void
		 */
		public function markAsBusy(string $taskName, DateTime $dateTime): void {
			// Get the file paths for the lock file and task file
			$lockFile = $this->getLockFilePath($taskName);
			$taskFile = $this->getTaskFilePath($taskName);
			
			// Acquire an exclusive lock to prevent race conditions
			$this->acquireLock($lockFile);
			
			try {
				// Check if task is already busy while holding the lock
				// This prevents race conditions where two processes might try to mark the same task as busy
				if ($this->isTaskBusyUnsafe($taskName)) {
					throw new RuntimeException("Task '{$taskName}' is already busy");
				}
				
				// Write the task information to the task file
				$this->writeTaskFile($taskFile, $taskName, $dateTime);
			} finally {
				// Always release the lock, even if an exception occurs
				// This ensures we don't leave the system in a locked state
				$this->releaseLock($lockFile);
			}
		}
		
		/**
		 * Mark a task as done
		 * @param string $taskName
		 * @param DateTime $dateTime
		 * @return void
		 */
		public function markAsDone(string $taskName, DateTime $dateTime): void {
			// Get the file paths for the lock file and task file
			$lockFile = $this->getLockFilePath($taskName);
			$taskFile = $this->getTaskFilePath($taskName);
			
			// Acquire an exclusive lock to prevent race conditions
			$this->acquireLock($lockFile);
			
			try {
				// Check if the task file exists before attempting to remove it
				// If it exists but deletion fails, throw an exception
				if (file_exists($taskFile) && !unlink($taskFile)) {
					throw new RuntimeException("Failed to remove task file: {$taskFile}");
				}
				
				// Note: If the file doesn't exist, the task is already considered "done"
				// so we don't need to do anything (idempotent operation)
			} finally {
				// Always release the lock, even if an exception occurs
				// This prevents leaving the system in a locked state
				$this->releaseLock($lockFile);
			}
		}
		
		/**
		 * Returns true if the task is currently busy, false if not
		 * @param string $taskName
		 * @return bool
		 */
		public function isBusy(string $taskName): bool {
			// Get the lock file path for this specific task
			$lockFile = $this->getLockFilePath($taskName);
			
			// Acquire an exclusive lock to ensure consistent read
			// This prevents race conditions where the task status might change
			// while we're checking it
			$this->acquireLock($lockFile);
			
			try {
				// Check the task status using the unsafe method
				// (unsafe because it doesn't handle locking internally)
				return $this->isTaskBusyUnsafe($taskName);
			} finally {
				// Always release the lock, even if an exception occurs
				// This ensures we don't leave the system in a locked state
				$this->releaseLock($lockFile);
			}
		}
		
		/**
		 * Clean up stale task files and locks
		 * @return void
		 */
		public function cleanup(): void {
			// Scan the storage directory for files to clean up
			// Use @ to suppress warnings if the directory can't be read
			$files = @scandir($this->storageDirectory);
			
			if ($files === false) {
				// Log a warning if we can't read the directory, but don't throw an exception
				// This allows the application to continue running even if cleanup fails
				error_log("Warning: Failed to scan directory for cleanup: {$this->storageDirectory}");
				return;
			}
			
			// Iterate through all files in the storage directory
			foreach ($files as $filename) {
				// Skip the current directory (.) and parent directory (..) entries
				if ($filename === '.' || $filename === '..') {
					continue;
				}
				
				// Build the full file path
				$filePath = $this->storageDirectory . '/' . $filename;
				
				// Handle task files (.task extension)
				if (str_ends_with($filename, '.task')) {
					$this->cleanupTaskFileIfStale($filePath);
					continue;
				}
				
				// Handle lock files (.lock extension)
				if (str_ends_with($filename, '.lock')) {
					// Only clean up lock files that we don't currently own
					// This prevents us from accidentally removing our own active locks
					if (!isset($this->acquiredLocks[$filePath])) {
						$this->cleanupLockFileIfStale($filePath);
					}
				}
			}
		}
		
		/**
		 * Ensure storage (tables, files, etc.) exists
		 * @return void
		 */
		private function ensureStorage(): void {
			// Check if the storage directory exists
			if (!is_dir($this->storageDirectory)) {
				// Attempt to create the directory with proper permissions (0755)
				// The third parameter 'true' enables recursive directory creation
				if (!mkdir($this->storageDirectory, 0755, true)) {
					throw new RuntimeException("Failed to create storage directory: {$this->storageDirectory}");
				}
			}
			
			// Verify that the storage directory is writable
			// This ensures we can create/modify files within it
			if (!is_writable($this->storageDirectory)) {
				throw new RuntimeException("Storage directory is not writable: {$this->storageDirectory}");
			}
		}
		
		/**
		 * Write task data to file
		 * @param string $taskFile
		 * @param string $taskName
		 * @param DateTime $dateTime
		 * @return void
		 */
		private function writeTaskFile(string $taskFile, string $taskName, DateTime $dateTime): void {
			// Create a data structure with task information
			$taskData = [
				'task_name'  => $taskName,                          // Human-readable task name
				'started_at' => $dateTime->format('Y-m-d H:i:s'),  // Formatted timestamp for readability
				'timestamp'  => $dateTime->getTimestamp(),          // Unix timestamp for calculations
				'pid'        => getmypid(),                         // Process ID for debugging/identification
				'hostname'   => gethostname()                       // Server hostname for distributed systems
			];
			
			// Convert the task data to JSON format with pretty printing
			// This makes the file human-readable for debugging purposes
			$jsonData = json_encode($taskData, JSON_PRETTY_PRINT);
			
			// Write the JSON data to the task file
			// LOCK_EX ensures exclusive access during the write operation
			// This prevents corruption if multiple processes try to write simultaneously
			if (file_put_contents($taskFile, $jsonData, LOCK_EX) === false) {
				throw new RuntimeException("Failed to write task file: {$taskFile}");
			}
		}
		
		/**
		 * Check if the task is busy without acquiring lock (internal use)
		 * @param string $taskName
		 * @return bool
		 */
		private function isTaskBusyUnsafe(string $taskName): bool {
			// Get the file path for this task
			$taskFile = $this->getTaskFilePath($taskName);
			
			// If the task file doesn't exist, the task is not busy
			if (!file_exists($taskFile)) {
				return false;
			}
			
			// Read and parse the task data from the file
			$taskData = $this->readTaskFile($taskFile);
			
			// If we can't read or parse the task data, consider it invalid
			// Remove the corrupted file and return false
			if ($taskData === null) {
				@unlink($taskFile);  // @ suppresses warnings if file deletion fails
				return false;
			}
			
			// Check if the task is stale (e.g., process died, exceeded timeout)
			if ($this->isTaskStale($taskData)) {
				@unlink($taskFile);  // Clean up stale task file
				return false;
			}
			
			// If we reach here, the task file exists, is valid, and not stale
			return true;
		}
		
		/**
		 * Check if task is stale based on process and time
		 * @param array $taskData
		 * @return bool
		 */
		private function isTaskStale(array $taskData): bool {
			// Check if the process that created this task is still running
			if (isset($taskData['pid']) && function_exists('posix_kill')) {
				// Fetch the pid
				$pid = (int)$taskData['pid'];
				
				// Use posix_kill with signal 0 to check if process exists
				// Signal 0 doesn't actually send a signal, just checks if process exists
				if ($pid > 0 && !posix_kill($pid, 0)) {
					return true;  // Process is dead, task is stale
				}
			}
			
			// Check if the task has exceeded its timeout duration
			if (isset($taskData['timestamp'])) {
				// Add a 5-minute buffer to the lock timeout to account for processing delays
				// This prevents premature cleanup of tasks that are still legitimately running
				$currentTime = time();
				$taskStartTime = (int)$taskData['timestamp'];
				$timeoutWithBuffer = $this->lockTimeout + 300; // 5 minute buffer
				
				// If the task has been running longer than the timeout + buffer, it's stale
				if (($currentTime - $taskStartTime) > $timeoutWithBuffer) {
					return true;
				}
			}
			
			// If neither staleness condition is met, the task is still valid
			return false;
		}
		
		/**
		 * Read and parse task file
		 * @param string $taskFile
		 * @return array|null
		 */
		private function readTaskFile(string $taskFile): ?array {
			// Read the file contents, suppressing warnings if file doesn't exist or can't be read
			// Using @ to handle race conditions where the file might be deleted between checks
			$content = @file_get_contents($taskFile);
			
			// If we couldn't read the file, return null to indicate failure
			if ($content === false) {
				return null;
			}
			
			// Parse the JSON content into an associative array
			$data = json_decode($content, true);
			
			// Check if JSON parsing was successful
			// If there was a JSON parsing error, the file is corrupted
			if (json_last_error() !== JSON_ERROR_NONE) {
				return null;
			}
			
			// Return the successfully parsed task data
			return $data;
		}
		
		/**
		 * Get file paths for task and lock files
		 * @param string $taskName
		 * @return string
		 */
		private function getTaskFilePath(string $taskName): string {
			// Build the full path for the task file
			// Uses sanitized task name to prevent directory traversal attacks
			// and ensures valid filenames across different operating systems
			return $this->storageDirectory . DIRECTORY_SEPARATOR . $this->sanitizeTaskName($taskName) . '.task';
		}
		
		private function getLockFilePath(string $taskName): string {
			// Build the full path for the lock file
			// Uses the same sanitization as task files to ensure consistency
			// Lock files use .lock extension to distinguish from task files
			return $this->storageDirectory . DIRECTORY_SEPARATOR . $this->sanitizeTaskName($taskName) . '.lock';
		}
		/**
		 * Sanitize task name for use as filename
		 * @param string $taskName
		 * @return string
		 */
		private function sanitizeTaskName(string $taskName): string {
			// Replace any character that's not alphanumeric, underscore, or hyphen with underscore
			// This prevents directory traversal attacks (e.g., "../../../etc/passwd")
			// and ensures compatibility across different filesystems and operating systems
			$sanitized = preg_replace('/[^a-zA-Z0-9_-]/', '_', $taskName);
			
			// Limit the filename length to 100 characters
			// This prevents filesystem errors on systems with filename length limits
			// and keeps filenames manageable
			if (strlen($sanitized) > 100) {
				$sanitized = substr($sanitized, 0, 100);
			}
			
			return $sanitized;
		}
		
		/**
		 * Acquire an exclusive lock with exponential backoff
		 * @param string $lockFile
		 * @return void
		 */
		private function acquireLock(string $lockFile): void {
			// Track timing and backoff state
			$startTime = microtime(true);
			$currentBackoffMs = self::INITIAL_BACKOFF_MS;
			$attempt = 0;
			
			while (true) {
				$attempt++;
				
				// Try to acquire the lock
				if ($this->tryAcquireLock($lockFile)) {
					// Successfully acquired lock - track it to prevent cleanup of our own locks
					$this->acquiredLocks[$lockFile] = [
						'pid'  => getmypid(),  // Process ID for debugging
						'time' => time()       // Acquisition time for staleness checks
					];
					return;
				}
				
				// If lock acquisition failed, try to clean up stale locks
				if ($this->tryCleanupStaleLock($lockFile)) {
					// Reset backoff after successful cleanup since we made progress
					$currentBackoffMs = self::INITIAL_BACKOFF_MS;
					continue;  // Try acquiring lock again immediately
				}
				
				// Check if we've exceeded the maximum wait time
				if ((microtime(true) - $startTime) > $this->maxLockWaitTime) {
					throw new RuntimeException(
						"Failed to acquire lock within {$this->maxLockWaitTime} seconds after {$attempt} attempts: {$lockFile}"
					);
				}
				
				// Apply exponential backoff with jitter to reduce thundering herd
				$jitterRange = $currentBackoffMs * self::JITTER_FACTOR;
				$jitter = mt_rand(-$jitterRange * 1000, $jitterRange * 1000) / 1000;
				$sleepTimeMs = max(1, (int)($currentBackoffMs + $jitter));
				
				// Sleep for the calculated backoff time (convert ms to microseconds)
				usleep($sleepTimeMs * 1000);
				
				// Increase backoff for next iteration, capped at maximum
				$currentBackoffMs = min($currentBackoffMs * self::BACKOFF_MULTIPLIER, self::MAX_BACKOFF_MS);
			}
		}
		
		/**
		 * Try to acquire lock atomically
		 * @param string $lockFile
		 * @return bool
		 */
		private function tryAcquireLock(string $lockFile): bool {
			// Attempt to create the lock file atomically using 'x' mode
			// 'x' mode creates the file ONLY if it doesn't exist, providing atomicity
			// @ suppresses warnings if the file already exists (expected behavior)
			$lockHandle = @fopen($lockFile, 'x');
			
			// If file creation failed, the lock is already held by another process
			if ($lockHandle === false) {
				return false;
			}
			
			// Write lock metadata to the file for debugging and staleness detection
			// Format: PID on first line, timestamp on second line
			fwrite($lockHandle, getmypid() . "\n" . time());
			fclose($lockHandle);
			
			// Successfully acquired the lock
			return true;
		}
		
		/**
		 * Try to cleanup stale lock
		 * @param string $lockFile
		 * @return bool
		 */
		private function tryCleanupStaleLock(string $lockFile): bool {
			// If the lock file doesn't exist, there's nothing to clean up
			if (!file_exists($lockFile)) {
				return false;
			}
			
			// Read and parse the lock file data (PID and timestamp)
			$lockData = $this->readLockFile($lockFile);
			
			// If we can't read the lock data (corrupted file) or the lock is stale,
			// attempt to remove the lock file
			if ($lockData === null || $this->isLockStale($lockData)) {
				// Use @ to suppress warnings if file deletion fails
				// Return true if deletion succeeded, false if it failed
				return @unlink($lockFile);
			}
			
			// Lock exists and is still valid - don't clean it up
			return false;
		}
		
		/**
		 * Read lock file data and check if lock is stale
		 * @param string $lockFile
		 * @return array|null
		 */
		private function readLockFile(string $lockFile): ?array {
			// Read the lock file contents, suppressing warnings if file doesn't exist
			// or can't be read (handles race conditions where file might be deleted)
			$lockContent = @file_get_contents($lockFile);
			
			// If we couldn't read the file, return null to indicate failure
			if ($lockContent === false) {
				return null;
			}
			
			// Split the content by newlines and remove any trailing whitespace
			// Expected format: PID on first line, timestamp on second line
			$lines = explode("\n", trim($lockContent));
			
			// Validate that we have at least the required two lines (PID and timestamp)
			if (count($lines) < 2) {
				return null;  // Corrupted or incomplete lock file
			}
			
			// Parse and return the lock data as an associative array
			return [
				'pid'  => (int)$lines[0],  // Process ID that created the lock
				'time' => (int)$lines[1]   // Unix timestamp when lock was created
			];
		}
		
		/**
		 * Check if a lock is stale based on timeout and process status
		 * @param array $lockData Lock data containing 'pid' and 'time' keys
		 * @return bool True if the lock is stale, false if still valid
		 */
		private function isLockStale(array $lockData): bool {
			// Check if the lock has exceeded its timeout duration
			// Compare current time with lock creation time
			if ((time() - $lockData['time']) > $this->lockTimeout) {
				return true;  // Lock has timed out and is considered stale
			}
			
			// Check if the process that created the lock is still running
			if (function_exists('posix_kill') && $lockData['pid'] > 0) {
				// Use posix_kill with signal 0 to check if process exists
				// Signal 0 doesn't actually send a signal, just tests process existence
				// Returns true if process exists, false if it doesn't
				return !posix_kill($lockData['pid'], 0);  // Stale if process is dead
			}
			
			// If we can't check process status (no posix_kill) and timeout hasn't been reached,
			// assume the lock is still valid
			return false;
		}
		
		/**
		 * Release the lock with ownership validation
		 * @param string $lockFile
		 * @return void
		 */
		private function releaseLock(string $lockFile): void {
			// Validate that we own this lock
			if (!$this->validateLockOwnership($lockFile)) {
				error_log("Warning: Attempted to release lock not owned by current process: {$lockFile}");
				return;
			}
			
			// Remove from our tracked locks
			unset($this->acquiredLocks[$lockFile]);
			
			// Remove the lock file
			@unlink($lockFile);
		}
		
		/**
		 * Validate that the current process owns the lock
		 * @param string $lockFile
		 * @return bool
		 */
		private function validateLockOwnership(string $lockFile): bool {
			// First check our internal tracking
			if (!isset($this->acquiredLocks[$lockFile])) {
				return false;
			}
			
			// Verify the lock file still exists and matches our PID
			if (!file_exists($lockFile)) {
				// Lock file was removed externally, clean up our tracking
				unset($this->acquiredLocks[$lockFile]);
				return false;
			}
			
			$lockData = $this->readLockFile($lockFile);
			
			if ($lockData === null || $lockData['pid'] !== getmypid()) {
				unset($this->acquiredLocks[$lockFile]);
				return false;
			}
			
			// Verify the timestamp roughly matches when we acquired it
			$acquiredTime = $this->acquiredLocks[$lockFile]['time'];
			$lockTime = $lockData['time'];
			
			// Allow some tolerance for clock skew (5 seconds)
			if (abs($lockTime - $acquiredTime) > 5) {
				unset($this->acquiredLocks[$lockFile]);
				return false;
			}
			
			return true;
		}
		
		/**
		 * Clean up task file if it's stale
		 * @param string $taskFile
		 * @return void
		 */
		private function cleanupTaskFileIfStale(string $taskFile): void {
			// Read and parse the task file data
			$taskData = $this->readTaskFile($taskFile);
			
			// If we can't read or parse the task file, it's corrupted - remove it
			if ($taskData === null) {
				@unlink($taskFile);  // @ suppresses warnings if file deletion fails
				return;
			}
			
			// If the task data doesn't have a timestamp, we can't determine staleness
			// Keep the file since we can't safely determine if it's stale
			if (!isset($taskData['timestamp'])) {
				return;
			}
			
			// Calculate if the task has exceeded its timeout
			// Add 5-minute buffer to prevent premature cleanup of legitimate tasks
			$currentTime = time();
			$taskStartTime = (int)$taskData['timestamp'];
			$timeoutWithBuffer = $this->lockTimeout + 300;
			
			// If the task has been running longer than timeout + buffer, remove it
			if (($currentTime - $taskStartTime) > $timeoutWithBuffer) {
				@unlink($taskFile);  // Clean up stale task file
			}
		}
		
		/**
		 * Clean up lock file if it's stale
		 * @param string $lockFile
		 * @return void
		 */
		private function cleanupLockFileIfStale(string $lockFile): void {
			// Read and parse the lock file data (PID and timestamp)
			$lockData = $this->readLockFile($lockFile);
			
			// Remove the lock file if:
			// 1. We can't read/parse the lock data (corrupted file), OR
			// 2. The lock is determined to be stale (process dead or timed out)
			if ($lockData === null || $this->isLockStale($lockData)) {
				@unlink($lockFile);  // @ suppresses warnings if file deletion fails
			}
		}
	}