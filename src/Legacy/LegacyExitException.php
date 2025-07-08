<?php
	
	namespace Quellabs\Canvas\Legacy;
	
	/**
	 * Exception thrown when legacy code calls exit() or die()
	 *
	 * This custom exception is designed to handle cases where legacy PHP code
	 * contains exit() or die() statements that would normally terminate script
	 * execution. By throwing this exception instead, the application can catch
	 * and handle the exit gracefully without stopping the entire process.
	 */
	class LegacyExitException extends \Exception {
	
		/**
		 * The exit code that would have been used with exit() or die()
		 * @var int
		 */
		private int $exitCode;
		
		/**
		 * Constructor for LegacyExitException
		 * @param int $exitCode The exit code (0 for success, non-zero for error)
		 * @param string $message Optional message describing the exit condition
		 */
		public function __construct(int $exitCode = 0, string $message = 'Legacy exit called') {
			// Call parent Exception constructor with the message
			parent::__construct($message);
			
			// Store the exit code for later retrieval
			$this->exitCode = $exitCode;
		}
		
		/**
		 * Get the exit code associated with this exception
		 *
		 * This allows calling code to determine what exit code the legacy
		 * code was trying to use, which can be useful for determining
		 * whether the exit was due to success (0) or an error (non-zero).
		 *
		 * @return int The exit code
		 */
		public function getExitCode(): int {
			return $this->exitCode;
		}
	}