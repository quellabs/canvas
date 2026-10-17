<?php

	namespace Quellabs\Canvas\Exceptions;

	/**
	 * Exception thrown when a route pattern is structurally invalid and cannot
	 * be compiled, e.g. a partial-variable segment that declares the same
	 * variable name twice (such as "{id}-{id}"). Thrown at route-compile time
	 * (controller discovery / app bootstrap), not at request time, so a bad
	 * route definition fails loudly instead of silently never matching.
	 */
	class InvalidRouteDefinitionException extends \Exception {
	}
