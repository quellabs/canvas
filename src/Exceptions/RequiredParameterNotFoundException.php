<?php

	namespace Quellabs\Canvas\Exceptions;

	/**
	 * Thrown when a required (non-nullable) controller parameter was resolved by
	 * a dependency-injection provider to no value at all — e.g. no database row
	 * for the requested entity. Carries HTTP code 404 via HttpException.
	 */
	class RequiredParameterNotFoundException extends HttpException {

		/**
		 * @param string $className Controller class that declares the parameter
		 * @param string $methodName Method that declares the parameter
		 * @param string $parameterName Name of the unresolved parameter
		 */
		public function __construct(string $className, string $methodName, string $parameterName) {
			parent::__construct(
				"No value available for required parameter '{$parameterName}' of {$className}::{$methodName}()",
				404
			);
		}
	}
