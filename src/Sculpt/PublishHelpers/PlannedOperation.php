<?php
	
	namespace Quellabs\Canvas\Sculpt\PublishHelpers;
	
	/**
	 * Represents a planned file operation within a transaction
	 *
	 * This class encapsulates the details of a file operation that will be
	 * executed as part of a publishing transaction, including the type of
	 * operation, source and target paths, and optional metadata.
	 */
	class PlannedOperation {
		/** @var string Operation type: copy a file to new location */
		public const string TYPE_COPY = 'copy';
		
		/** @var string Operation type: skip the file operation */
		public const string TYPE_SKIP = 'skip';
		
		/** @var string Operation type: overwrite existing file */
		public const string TYPE_OVERWRITE = 'overwrite';
		
		/**
		 * Create a new planned operation
		 * @param string $type The type of operation (copy, skip, or overwrite)
		 * @param string $sourcePath The path to the source file
		 * @param string $targetPath The path where the file should be placed
		 * @param string $reason Optional reason for this operation (e.g., why skipped)
		 * @param string|null $backupPath Optional path where original file is backed up before overwrite
		 */
		public function __construct(
			public readonly string $type,
			public readonly string $sourcePath,
			public readonly string $targetPath,
			public readonly string $reason = '',
			public readonly ?string $backupPath = null
		) {}
	}