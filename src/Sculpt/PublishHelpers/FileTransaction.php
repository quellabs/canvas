<?php
	
	namespace Quellabs\Canvas\Sculpt\PublishHelpers;
	
	/**
	 * Represents a file operation transaction with pre-planned operations
	 *
	 * This class encapsulates all planned file operations and their execution state,
	 * providing a complete transaction that knows what work needs to be done upfront.
	 */
	class FileTransaction {
		
		/**
		 * @var string Unique transaction identifier
		 */
		private string $id;
		
		/**
		 * @var float Transaction creation timestamp
		 */
		private float $createdAt;
		
		/**
		 * @var string|null Optional transaction description
		 */
		private ?string $description;
		
		/**
		 * @var array<PlannedOperation> Planned operations to execute
		 */
		private array $plannedOperations = [];
		
		/**
		 * @var array Executed operations log for rollback purposes
		 */
		private array $executedOperations = [];
		
		/**
		 * @var bool Whether this transaction has been executed
		 */
		private bool $executed = false;
		
		/**
		 * Executed operation types for logging
		 */
		public const string OP_FILE_COPY = 'file_copy';
		public const string OP_BACKUP_CREATE = 'backup_create';
		public const string OP_DIRECTORY_CREATE = 'directory_create';
		
		/**
		 * FileTransaction constructor
		 *
		 * @param array $publishData Publishing configuration containing manifest and paths
		 * @param bool $overwrite Whether to overwrite existing files
		 * @param string|null $description Optional description for the transaction
		 * @throws FileOperationException If planning fails
		 */
		public function __construct(array $publishData, bool $overwrite = false, ?string $description = null) {
			$this->id = uniqid('txn_', true);
			$this->createdAt = microtime(true);
			$this->description = $description;
			
			$this->planOperations($publishData, $overwrite);
		}
		
		/**
		 * Plan all operations based on the publish data and overwrite setting
		 * @param array $publishData Publishing configuration
		 * @param bool $overwrite Whether to overwrite existing files
		 * @return void
		 * @throws FileOperationException If planning fails
		 */
		private function planOperations(array $publishData, bool $overwrite): void {
			// Iterate through each file defined in the manifest
			foreach ($publishData['manifest']['files'] as $file) {
				// Build the full source path by combining base directory with relative file path
				$sourcePath = $this->buildSourcePath($publishData['sourceDirectory'], $file['source']);
				
				// Resolve the target path where the file should be published
				$targetPath = $this->resolveTargetPath($file['target'], $publishData['projectRoot']);
				
				// Validate source file exists before planning any operations
				if (!file_exists($sourcePath)) {
					throw new FileOperationException("Source file not found during planning: {$sourcePath}");
				}
				
				// Ensure the source file is readable
				if (!is_readable($sourcePath)) {
					throw new FileOperationException("Source file is not readable during planning: {$sourcePath}");
				}
				
				// If target file doesn't exist, plan a simple copy operation
				if (!file_exists($targetPath)) {
					$this->plannedOperations[] = new PlannedOperation(
						PlannedOperation::TYPE_COPY,
						$sourcePath,
						$targetPath,
						'New file'
					);
					continue;
				}
				
				// Target file exists - check if overwrite is disabled
				if (!$overwrite) {
					// Skip this file to preserve the existing version
					$this->plannedOperations[] = new PlannedOperation(
						PlannedOperation::TYPE_SKIP,
						$sourcePath,
						$targetPath,
						'Target exists, overwrite disabled'
					);
					
					continue;
				}
				
				// Target exists and overwrite is enabled - create backup and plan overwrite
				$backupPath = $this->generateUniqueBackupPath($targetPath);
				
				$this->plannedOperations[] = new PlannedOperation(
					PlannedOperation::TYPE_OVERWRITE,
					$sourcePath,
					$targetPath,
					'Target exists, will overwrite',
					$backupPath
				);
			}
		}
		
		/**
		 * Generate a unique backup path with timestamp
		 * @param string $targetPath Original file path
		 * @return string Unique backup path
		 */
		private function generateUniqueBackupPath(string $targetPath): string {
			// Create timestamp in readable format (YYYY-MM-DD_HH-MM-SS)
			$timestamp = date('Y-m-d_H-i-s');
			
			// Build initial backup path by appending timestamp to original path
			$backupPath = $targetPath . '.backup.' . $timestamp;
			
			// Initialize counter for handling collisions if multiple backups occur in same second
			$counter = 1;
			
			// Check if backup file already exists (handles edge case of rapid successive calls)
			while (file_exists($backupPath)) {
				// Append counter to make path unique if timestamp collision occurs
				$backupPath = $targetPath . '.backup.' . $timestamp . '_' . $counter;
				
				// Increment counter for next iteration
				$counter++;
			}
			
			// Return the guaranteed unique backup path
			return $backupPath;
		}
		
		/**
		 * Get the transaction ID
		 * @return string Transaction ID
		 */
		public function getId(): string {
			return $this->id;
		}
		
		/**
		 * Get the transaction creation timestamp
		 * @return float Creation timestamp
		 */
		public function getCreatedAt(): float {
			return $this->createdAt;
		}
		
		/**
		 * Get the transaction description
		 * @return string|null Transaction description
		 */
		public function getDescription(): ?string {
			return $this->description;
		}
		
		/**
		 * Get all planned operations
		 * @return array<PlannedOperation> Array of planned operations
		 */
		public function getPlannedOperations(): array {
			return $this->plannedOperations;
		}
		
		/**
		 * Get all executed operations
		 * @return array Array of executed operations
		 */
		public function getExecutedOperations(): array {
			return $this->executedOperations;
		}
		
		/**
		 * Check if the transaction has been executed
		 * @return bool True if executed
		 */
		public function isExecuted(): bool {
			return $this->executed;
		}
		
		/**
		 * Mark transaction as executed
		 * @return void
		 */
		public function markExecuted(): void {
			$this->executed = true;
		}
		
		/**
		 * Add an executed operation to the transaction log
		 * @param string $type Operation type (one of the OP_* constants)
		 * @param array $data Operation-specific data for rollback purposes
		 * @return void
		 */
		public function logExecutedOperation(string $type, array $data): void {
			$this->executedOperations[] = [
				'type'      => $type,
				'data'      => $data,
				'timestamp' => microtime(true)
			];
		}
		
		/**
		 * Get operation summary including planned and executed operations
		 * @return array Summary of operations
		 */
		public function getSummary(): array {
			// Initialize counters for planned operations
			$plannedSummary = [
				'copy'      => 0,
				'overwrite' => 0,
				'skip'      => 0,
			];
			
			// Count each type of planned operation
			foreach ($this->plannedOperations as $operation) {
				$plannedSummary[$operation->type]++;
			}
			
			// Initialize counters for executed operations
			$executedSummary = [
				'file_copies'         => 0,
				'backups_created'     => 0,
				'directories_created' => 0,
			];
			
			// Count each type of executed operation based on operation type constants
			foreach ($this->executedOperations as $operation) {
				switch ($operation['type']) {
					case self::OP_FILE_COPY:
						$executedSummary['file_copies']++;
						break;
					case self::OP_BACKUP_CREATE:
						$executedSummary['backups_created']++;
						break;
					case self::OP_DIRECTORY_CREATE:
						$executedSummary['directories_created']++;
						break;
				}
			}
			
			// Return comprehensive summary with transaction metadata and operation counts
			return [
				'transaction_id'      => $this->id,           // Unique identifier for this transaction
				'created_at'          => $this->createdAt,    // When the transaction was created
				'description'         => $this->description,  // Human-readable description
				'executed'            => $this->executed,     // Whether transaction has been executed
				'planned'             => $plannedSummary,     // Counts of planned operations by type
				'executed_operations' => $executedSummary,    // Counts of actual operations performed
			];
		}
		
		/**
		 * Check if a path is absolute
		 * @param string $path Path to check
		 * @return bool True if path is absolute, false if relative
		 */
		private function isAbsolutePath(string $path): bool {
			return $path[0] === '/' || (strlen($path) > 1 && $path[1] === ':');
		}
		
		/**
		 * Resolve the target path, making it absolute if relative
		 * @param string $targetPath Target path (may be relative)
		 * @param string $projectRoot Project root directory
		 * @return string Absolute target path
		 */
		private function resolveTargetPath(string $targetPath, string $projectRoot): string {
			if ($this->isAbsolutePath($targetPath)) {
				return $targetPath;
			}
			
			return rtrim($projectRoot, '/') . '/' . ltrim($targetPath, '/');
		}
		
		/**
		 * Build the complete source path from directory and relative path
		 * @param string $sourceDirectory Base source directory
		 * @param string $relativePath Relative path to the file
		 * @return string Complete source path
		 */
		private function buildSourcePath(string $sourceDirectory, string $relativePath): string {
			return rtrim($sourceDirectory, '/') . '/' . ltrim($relativePath, '/');
		}
	}