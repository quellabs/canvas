<?php
	
	namespace Quellabs\Canvas\Sculpt\PublishHelpers;
	
	use Quellabs\Contracts\IO\ConsoleOutput;
	
	/**
	 * This class executes pre-planned FileTransaction objects with proper commit/rollback
	 * functionality. Transactions contain all planned operations and can be executed,
	 * committed, or rolled back as atomic units.
	 */
	class FileOperationManager {

		/**
		 * @var ConsoleOutput Console output for logging operations
		 */
		private ConsoleOutput $output;
		
		/**
		 * TransactionalFileOperationManager constructor
		 * @param ConsoleOutput $output Console output interface for logging
		 */
		public function __construct(ConsoleOutput $output) {
			$this->output = $output;
		}
		
		/**
		 * Create a new transaction with planned operations
		 * @param array $publishData Publishing configuration containing manifest and paths
		 * @param bool $overwrite Whether to overwrite existing files
		 * @param string|null $description Optional description for the transaction
		 * @return FileTransaction New transaction object with planned operations
		 * @throws FileOperationException
		 */
		public function createTransaction(array $publishData, bool $overwrite = false, ?string $description = null): FileTransaction {
			return new FileTransaction($publishData, $overwrite, $description);
		}
		
		/**
		 * Show a preview of what the transaction will do
		 * @param FileTransaction $transaction Transaction to preview
		 * @return void
		 */
		public function previewTransaction(FileTransaction $transaction): void {
			// Display the transaction header with ID for identification
			$this->output->writeLn("<info>Transaction Preview: {$transaction->getId()}</info>");
			
			// Iterate through all planned operations in the transaction
			foreach ($transaction->getPlannedOperations() as $operation) {
				// Select appropriate visual icon based on operation type
				// This provides quick visual identification of what each operation will do
				$icon = match ($operation->type) {
					PlannedOperation::TYPE_COPY => '✓',      // Green checkmark for safe copy operations
					PlannedOperation::TYPE_OVERWRITE => '⚠', // Warning symbol for potentially destructive overwrites
					PlannedOperation::TYPE_SKIP => '•',      // Bullet point for skipped operations
					default => '?'                           // Question mark for unknown operation types
				};
				
				// Display each operation with:
				// - Visual icon for quick identification
				// - Operation type for clarity
				// - Source and target paths showing the file movement
				// - Reason explaining why this operation was chosen
				$this->output->writeLn("  {$icon} {$operation->type}: {$operation->sourcePath} → {$operation->targetPath} ({$operation->reason})");
			}
			
			// Get transaction summary statistics
			$summary = $transaction->getSummary();
			
			// Add spacing for better readability
			$this->output->writeLn("");
			
			// Display summary statistics showing total count of each operation type
			// This gives users a quick overview of what the transaction will accomplish
			$this->output->writeLn("<comment>Summary: {$summary['planned']['copy']} copies, {$summary['planned']['overwrite']} overwrites, {$summary['planned']['skip']} skips</comment>");
		}
		
		/**
		 * Commit the specified transaction, executing all planned operations and making them permanent
		 * @param FileTransaction $transaction Transaction to commit
		 * @return bool True if commit was successful
		 * @throws FileOperationException If transaction was already committed or operations fail
		 */
		public function commit(FileTransaction $transaction): bool {
			// Do nothing when the transaction was already committed
			if ($transaction->isExecuted()) {
				return true;
			}
			
			// Execute all planned operations
			foreach ($transaction->getPlannedOperations() as $operation) {
				$this->executeOperation($transaction, $operation);
			}
			
			// Mark the transaction as executed so we don't commit it twice
			$transaction->markExecuted();
			
			// Clean up any backup files since we're committing successfully
			$this->cleanupTransactionBackups($transaction);

			// Done!
			return true;
		}
		
		/**
		 * Rollback the specified transaction, undoing executed operations
		 * If the transaction was not yet executed, this is a no-op
		 * If the transaction was partially or fully executed, this undoes those operations
		 * @param FileTransaction $transaction Transaction to rollback
		 * @return void
		 * @throws RollbackException
		 */
		public function rollback(FileTransaction $transaction): void {
			$errors = [];
			$operations = array_reverse($transaction->getExecutedOperations()); // Reverse order for proper rollback
			
			foreach ($operations as $operation) {
				try {
					$this->rollbackOperation($operation);
				} catch (\Exception $e) {
					$errors[] = $e->getMessage();
				}
			}
			
			if (empty($errors)) {
				throw new RollbackException($errors);
			}
		}
		
		/**
		 * Execute a single planned operation
		 * @param FileTransaction $transaction Transaction context
		 * @param PlannedOperation $operation Operation to execute
		 * @return void
		 * @throws FileOperationException If operation fails
		 */
		private function executeOperation(FileTransaction $transaction, PlannedOperation $operation): void {
			switch ($operation->type) {
				case PlannedOperation::TYPE_SKIP:
					$this->output->writeLn("  • Skipped: {$operation->targetPath} (already exists)");
					break;
				
				case PlannedOperation::TYPE_COPY:
				case PlannedOperation::TYPE_OVERWRITE:
					$this->executeCopyOperation($transaction, $operation);
					break;
				
				default:
					throw new FileOperationException("Unknown planned operation type: {$operation->type}");
			}
		}
		
		/**
		 * Execute a copy or overwrite operation
		 * @param FileTransaction $transaction Transaction context
		 * @param PlannedOperation $operation Operation to execute
		 * @return void
		 * @throws FileOperationException If copy fails
		 */
		private function executeCopyOperation(FileTransaction $transaction, PlannedOperation $operation): void {
			// Create backup if overwriting (using the pre-planned backup path)
			if ($operation->type === PlannedOperation::TYPE_OVERWRITE) {
				$this->createBackupFile($transaction, $operation->targetPath, $operation->backupPath);
			}
			
			// Ensure target directory exists
			$this->ensureTargetDirectory($transaction, $operation->targetPath);
			
			// Perform the copy operation
			$this->performFileCopy($operation->sourcePath, $operation->targetPath);
			
			// Log the executed operation
			$transaction->logExecutedOperation(FileTransaction::OP_FILE_COPY, [
				'source'        => $operation->sourcePath,
				'target'        => $operation->targetPath,
				'was_overwrite' => $operation->type === PlannedOperation::TYPE_OVERWRITE,
				'backup_path'   => $operation->backupPath
			]);
			
			$action = $operation->type === PlannedOperation::TYPE_OVERWRITE ? 'Overwrote' : 'Copied';
			$this->output->writeLn("  ✓ {$action}: {$operation->sourcePath} → {$operation->targetPath}");
		}
		
		/**
		 * Create a timestamped backup of an existing file within the transaction
		 * @param FileTransaction $transaction Transaction context
		 * @param string $targetPath Path to the file that needs backing up
		 * @param string $backupPath Pre-planned backup path to use
		 * @return void
		 * @throws FileOperationException If backup creation fails
		 */
		private function createBackupFile(FileTransaction $transaction, string $targetPath, string $backupPath): void {
			if (!copy($targetPath, $backupPath)) {
				throw new FileOperationException("Failed to create backup: {$targetPath} → {$backupPath}");
			}
			
			$transaction->logExecutedOperation(FileTransaction::OP_BACKUP_CREATE, [
				'original' => $targetPath,
				'backup' => $backupPath
			]);
			
			$this->output->writeLn("  ✓ Backed up: {$targetPath} → {$backupPath}");
		}
		
		/**
		 * Ensure the target directory structure exists within the transaction
		 * @param FileTransaction $transaction Transaction context
		 * @param string $targetPath Full path to the target file
		 * @return void
		 * @throws FileOperationException If directory creation fails
		 */
		private function ensureTargetDirectory(FileTransaction $transaction, string $targetPath): void {
			// Extract the directory path from the full target file path
			$targetDir = dirname($targetPath);
			
			// Check if the directory already exists - no action needed if it does
			if (is_dir($targetDir)) {
				return;
			}
			
			// Attempt to create the directory with full permissions recursively
			// 0755 = owner: read/write/execute, group/others: read/execute
			if (!mkdir($targetDir, 0755, true)) {
				throw new FileOperationException("Failed to create target directory: {$targetDir}");
			}
			
			// Record the directory creation operation in the transaction log
			// This enables rollback functionality if the transaction fails
			$transaction->logExecutedOperation(FileTransaction::OP_DIRECTORY_CREATE, [
				'directory' => $targetDir
			]);
			
			// Provide user feedback about the directory creation
			$this->output->writeLn("  ✓ Created directory: {$targetDir}");
		}
		
		/**
		 * Perform the actual file copy operation with validation
		 * @param string $sourcePath Path to source file
		 * @param string $targetPath Path to target file
		 * @return void
		 * @throws FileOperationException If copy operation fails
		 */
		private function performFileCopy(string $sourcePath, string $targetPath): void {
			if (!copy($sourcePath, $targetPath)) {
				$error = error_get_last();
				$errorMessage = $error ? $error['message'] : 'Unknown error';
				
				throw new FileOperationException(
					"Failed to copy file: {$sourcePath} → {$targetPath}. Error: {$errorMessage}"
				);
			}
			
			// Verify the copy was successful
			$this->verifyCopyOperation($sourcePath, $targetPath);
		}
		
		/**
		 * Rollback a single operation based on its type
		 * @param array $operation Operation to rollback containing type and data
		 * @return void
		 * @throws FileOperationException If rollback fails or operation type is unknown
		 */
		private function rollbackOperation(array $operation): void {
			switch ($operation['type']) {
				case FileTransaction::OP_FILE_COPY:
					$this->rollbackFileCopy($operation['data']);
					break;
				
				case FileTransaction::OP_BACKUP_CREATE:
					$this->rollbackBackupCreate($operation['data']);
					break;
				
				case FileTransaction::OP_DIRECTORY_CREATE:
					$this->rollbackDirectoryCreate($operation['data']);
					break;
				
				default:
					throw new FileOperationException("Unknown operation type: {$operation['type']}");
			}
		}
		
		/**
		 * Rollback a file copy operation by removing the copied file and restoring backup if it was an overwrite
		 * @param array $data Operation data containing target path and backup info
		 * @return void
		 * @throws FileOperationException If file removal fails
		 */
		private function rollbackFileCopy(array $data): void {
			$targetPath = $data['target'];
			$backupPath = $data['backup_path'] ?? null;
			
			// If this was an overwrite operation and we have a backup, restore it
			if ($backupPath && file_exists($backupPath)) {
				if (!copy($backupPath, $targetPath)) {
					throw new FileOperationException("Failed to restore backup during rollback: {$backupPath} → {$targetPath}");
				}
				
				// Clean up the backup file after successful restore
				if (!unlink($backupPath)) {
					throw new FileOperationException("Failed to cleanup backup file during rollback: {$backupPath}");
				}
				
				$this->output->writeLn("  ✓ Restored from backup: {$targetPath}");
			} else {
				// This was a new file copy, just remove it
				if (file_exists($targetPath)) {
					if (!unlink($targetPath)) {
						throw new FileOperationException("Failed to remove copied file: {$targetPath}");
					}
					
					$this->output->writeLn("  ✓ Removed: {$targetPath}");
				}
			}
		}
		
		/**
		 * Rollback a backup creation by restoring the original file from backup
		 * @param array $data Operation data containing original and backup paths
		 * @return void
		 * @throws FileOperationException If backup restoration fails
		 */
		private function rollbackBackupCreate(array $data): void {
			$originalPath = $data['original'];
			$backupPath = $data['backup'];
			
			if (file_exists($backupPath)) {
				if (!copy($backupPath, $originalPath)) {
					throw new FileOperationException("Failed to restore backup: {$backupPath} → {$originalPath}");
				}
				
				// Clean up the backup file after successful restore
				if (!unlink($backupPath)) {
					throw new FileOperationException("Failed to cleanup backup file: {$backupPath}");
				}
				
				$this->output->writeLn("  ✓ Restored: {$backupPath} → {$originalPath}");
			}
		}
		
		/**
		 * Rollback a directory creation by removing the directory if it's empty
		 * @param array $data Operation data containing directory path
		 * @return void
		 * @throws FileOperationException If directory removal fails
		 */
		private function rollbackDirectoryCreate(array $data): void {
			$dirPath = $data['directory'];
			
			// Only remove if directory exists and is empty to avoid removing directories
			// that may have been populated by other processes or operations
			if (is_dir($dirPath) && $this->isDirectoryEmpty($dirPath)) {
				if (!rmdir($dirPath)) {
					throw new FileOperationException("Failed to remove created directory: {$dirPath}");
				}
				
				$this->output->writeLn("  ✓ Removed directory: {$dirPath}");
			}
		}
		
		/**
		 * Clean up backup files created during the specified transaction
		 * This is called during commit to remove temporary backup files that are no longer needed
		 * @param FileTransaction $transaction Transaction to clean up
		 * @return void
		 */
		private function cleanupTransactionBackups(FileTransaction $transaction): void {
			$cleanedCount = 0;
			
			foreach ($transaction->getExecutedOperations() as $operation) {
				if ($operation['type'] === FileTransaction::OP_BACKUP_CREATE) {
					$backupPath = $operation['data']['backup'];
					
					if (file_exists($backupPath)) {
						if (unlink($backupPath)) {
							$cleanedCount++;
						} else {
							$this->output->warning("Could not remove backup file: {$backupPath}");
						}
					}
				}
			}
			
			if ($cleanedCount > 0) {
				$this->output->writeLn("  ✓ Cleaned up {$cleanedCount} backup file(s)");
			}
		}
		
		/**
		 * Generate a unique backup path with timestamp
		 * @param string $targetPath Original file path
		 * @return string Unique backup path
		 */
		private function generateUniqueBackupPath(string $targetPath): string {
			$timestamp = date('Y-m-d_H-i-s');
			$backupPath = $targetPath . '.backup.' . $timestamp;
			
			// Ensure uniqueness for rapid successive calls
			$counter = 1;
			
			while (file_exists($backupPath)) {
				$backupPath = $targetPath . '.backup.' . $timestamp . '_' . $counter;
				$counter++;
			}
			
			return $backupPath;
		}
		
		/**
		 * Verify that copy operation was successful
		 * @param string $sourcePath Source file path
		 * @param string $targetPath Target file path
		 * @return void
		 * @throws FileOperationException If verification fails
		 */
		private function verifyCopyOperation(string $sourcePath, string $targetPath): void {
			// Check that target file exists
			if (!file_exists($targetPath)) {
				throw new FileOperationException(
					"Copy operation appeared successful but target file was not created: {$targetPath}"
				);
			}
			
			// Verify file sizes match
			$sourceSize = filesize($sourcePath);
			$targetSize = filesize($targetPath);
			
			if ($sourceSize !== $targetSize) {
				throw new FileOperationException(
					"File copy verification failed: size mismatch. Source: {$sourceSize} bytes, Target: {$targetSize} bytes"
				);
			}
		}
		
		/**
		 * Check if a directory is empty
		 * @param string $dirPath Directory path to check
		 * @return bool True if directory is empty, false otherwise
		 */
		private function isDirectoryEmpty(string $dirPath): bool {
			$handle = opendir($dirPath);
			
			while (false !== ($entry = readdir($handle))) {
				if ($entry != "." && $entry != "..") {
					closedir($handle);
					return false;
				}
			}
			
			closedir($handle);
			return true;
		}
	}
