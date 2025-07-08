<?php
	
	namespace Quellabs\Canvas\Sculpt\PublishHelpers;
	
	/**
	 * Custom exception for rollback operation errors
	 *
	 * This exception is thrown when rollback operations fail, providing
	 * specific context about what went wrong during the rollback process.
	 * It stores an array of errors that occurred during the rollback attempt.
	 */
	class RollbackException extends \Exception {
		
		/**
		 * Array of errors that occurred during the rollback operation
		 * @var array
		 */
		private array $errors;
		
		/**
		 * Creates a new rollback exception with an array of errors and optional message.
		 * The errors array should contain details about what specifically failed
		 * during the rollback process.
		 * @param array $errors Array of error details that occurred during rollback
		 * @param string $message Optional error message describing the overall failure
		 * @param int $code Optional error code (default: 0)
		 * @param \Throwable|null $previous Optional previous exception for exception chaining
		 */
		public function __construct(array $errors, string $message = "", int $code = 0, \Throwable $previous = null) {
			// Store the errors array for later retrieval
			$this->errors = $errors;
			
			// Call parent constructor to set up the base exception
			parent::__construct($message, $code, $previous);
		}
		
		/**
		 * Get the array of errors that occurred during rollback
		 * @return array The array of rollback errors
		 */
		public function getErrors(): array {
			return $this->errors;
		}
	}