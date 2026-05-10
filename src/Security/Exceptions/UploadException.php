<?php
	
	namespace Quellabs\Canvas\Security\Exceptions;
	
	use RuntimeException;
	
	/**
	 * Thrown by SecureUploadAspect when throwOnFailure is enabled and
	 * one or more uploaded files fail validation.
	 *
	 * The framework's exception handler is responsible for converting this
	 * into an appropriate HTTP response. Controllers that want to handle
	 * upload failures themselves (e.g. to re-render a form with per-file errors)
	 * should use the default attribute-based path instead of enabling throwOnFailure,
	 * or catch this exception explicitly in their own exception handler.
	 *
	 * The full per-file result set is preserved in $processedFiles so that an
	 * exception handler can still surface granular error information if needed.
	 */
	class UploadException extends RuntimeException {
		
		/** @var array<string, array<int, array<string, mixed>>> Per-field, per-file validation results */
		private array $processedFiles;
		
		/** @var string|null Batch-level error (e.g. too many files), if applicable */
		private ?string $batchError;
		
		/**
		 * @param string $message Human-readable summary of the failure
		 * @param array<string, array<int, array<string, mixed>>> $processedFiles Full per-file result set
		 * @param string|null $batchError Batch-level error string, or null if failure was per-file
		 */
		public function __construct(string $message, array $processedFiles = [], ?string $batchError = null) {
			parent::__construct($message);
			$this->processedFiles = $processedFiles;
			$this->batchError = $batchError;
		}
		
		/**
		 * Returns the per-field, per-file validation result array.
		 * Each entry contains a 'success' flag and an 'errors' array.
		 * @return array<string, array<int, array<string, mixed>>>
		 */
		public function getProcessedFiles(): array {
			return $this->processedFiles;
		}
		
		/**
		 * Returns the batch-level error string, or null if the failure was per-file only.
		 * @return string|null
		 */
		public function getBatchError(): ?string {
			return $this->batchError;
		}
	}