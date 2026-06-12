<?php
	
	namespace Quellabs\Canvas\Exceptions;
	
	use RuntimeException;
	
	/**
	 * Exception thrown when a requested route cannot be found
	 *
	 * This exception is used throughout the Canvas framework to indicate
	 * that neither Canvas routes nor legacy files can handle a request.
	 * It provides detailed information about the failed request for debugging.
	 */
	class RouteNotFoundException extends HttpException {
	}