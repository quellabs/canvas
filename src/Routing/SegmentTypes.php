<?php
	
	namespace Quellabs\Canvas\Routing;
	
	/**
	 * SegmentTypes
	 *
	 * Centralizes all segment type constants and type-checking logic to eliminate
	 * duplication and ensure consistency across the routing system.
	 *
	 * This class serves as the single source of truth for:
	 * - Segment type identifiers
	 * - Wildcard detection
	 * - Multi-segment consumption checks
	 * - Type categorization
	 */
	final class SegmentTypes {
		// Segment type constants
		public const string STATIC = 'static';
		public const string VARIABLE = 'variable';
		public const string SINGLE_WILDCARD = 'single_wildcard';
		public const string MULTI_WILDCARD = 'multi_wildcard';
		public const string MULTI_WILDCARD_VAR = 'multi_wildcard_var';
		public const string PARTIAL_VARIABLE = 'partial_variable';
		
		/**
		 * Check if segment type represents a multi-wildcard pattern
		 * Handles both anonymous (**) and named ({path:**}) wildcards
		 * @param array $segment
		 * @return bool
		 */
		public static function isMultiWildcard(array $segment): bool {
			return
				in_array($segment['type'], [self::MULTI_WILDCARD, self::MULTI_WILDCARD_VAR], true) ||
				($segment['type'] === self::VARIABLE && !empty($segment['is_multi_wildcard'])) ||
				($segment['type'] === self::PARTIAL_VARIABLE && !empty($segment['is_multi_wildcard']));
		}
		
		/**
		 * Check if segment type represents any wildcard pattern
		 * @param array $segment
		 * @return bool
		 */
		public static function isWildcard(array $segment): bool {
			return in_array($segment['type'], [
				self::SINGLE_WILDCARD,
				self::MULTI_WILDCARD,
				self::MULTI_WILDCARD_VAR
			], true);
		}
		
		/**
		 * Check if segment type is static (no variables)
		 * @param array $segment
		 * @return bool
		 */
		public static function isStatic(array $segment): bool {
			return $segment['type'] === self::STATIC;
		}
		
		/**
		 * Check if segment type contains variables
		 * @param array $segment
		 * @return bool
		 */
		public static function hasVariables(array $segment): bool {
			return in_array($segment['type'], [
				self::VARIABLE,
				self::PARTIAL_VARIABLE,
				self::SINGLE_WILDCARD,
				self::MULTI_WILDCARD,
				self::MULTI_WILDCARD_VAR
			], true);
		}
	}