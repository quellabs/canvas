<?php

	namespace Quellabs\Canvas\Routing;

	/**
	 * TypeConstraintResolver
	 *
	 * Single source of truth for mapping a route type constraint name
	 * (e.g. "int", "alpha", "uuid") to its matching regex fragment.
	 * Shared by RoutePatternCompiler (compile time) and PartialVariableStrategy
	 * (match time, when a partial-variable segment's regex failed to compile
	 * and matching falls back to manual prefix/suffix parsing).
	 */
	final class TypeConstraintResolver {
		// Static type pattern mappings for variable validation
		private const array TYPE_PATTERNS = [
			// Numeric types
			'int'          => '\d+',
			'integer'      => '\d+',

			// Text types
			'alpha'        => '[a-zA-Z]+',
			'alnum'        => '[a-zA-Z0-9]+',
			'alphanumeric' => '[a-zA-Z0-9]+',
			'word'         => '\w+',
			'slug'         => '[a-zA-Z0-9-]+',

			// Identifiers
			'uuid'         => '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',

			// Web-specific
			'email'        => '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',

			// Version/Code patterns
			'hex'          => '[a-fA-F0-9]+',
			'base64'       => '[a-zA-Z0-9+/=]+',

			// Common business patterns
			'sku'          => '[A-Z0-9\-]+',
			'isbn'         => '\d{3}-\d{1,5}-\d{1,7}-\d{1,7}-\d{1}',
			'phone'        => '\+?[0-9\-\s\(\)]+',
			'postal'       => '[A-Z0-9\s\-]+',

			// Locale/Language
			'locale'       => '[a-z]{2}(_[A-Z]{2})?',
			'language'     => '[a-z]{2,3}',
			'country'      => '[A-Z]{2}',
			'currency'     => '[A-Z]{3}',
		];

		/**
		 * Resolve a type constraint name to its regex pattern.
		 * @param string $type The type constraint (int, alpha, uuid, etc.)
		 * @return string The corresponding regex pattern
		 */
		public static function resolveTypeToRegex(string $type): string {
			return match ($type) {
				'*' => '[^\/]*',     // Single wildcard - any chars except path separator
				'**' => '.*',        // Multi-wildcard - any chars including path separators
				default => self::TYPE_PATTERNS[$type] ?? '[^\/]+'
			};
		}
	}
