<?php
	
	namespace Quellabs\Canvas\Exceptions;
	
	use RuntimeException;
	
	/**
	 * Base exception type for HTTP-related framework failures.
	 *
	 * These exceptions represent runtime request-handling failures that occur
	 * during normal application execution, such as missing routes, invalid
	 * CSRF tokens, failed uploads, or rate limiting.
	 *
	 */
	class HttpException extends RuntimeException {
	}