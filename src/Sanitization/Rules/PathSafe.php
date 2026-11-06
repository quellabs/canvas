<?php

	namespace Quellabs\Canvas\Sanitization\Rules;

	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;

	/**
	 * This class implements path sanitization by removing common path traversal
	 * patterns and null bytes that could be used to access files outside
	 * the intended directory structure.
	 */
	class PathSafe implements SanitizationRuleInterface {

		/**
		 * Sanitize a value to make it safe for use in file paths
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value, or original value if not a string
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - return other types unchanged
			if (!is_string($value)) {
				return $value;
			}

			// Remove null bytes (\0) which can be used to truncate paths
			// in some systems and bypass security checks
			$value = str_replace("\0", '', $value);

			// Strip a Windows drive prefix (e.g. "C:\") so the value can't escape
			// to an absolute path when the caller concatenates it onto a base directory
			$value = preg_replace('#^[A-Za-z]:[\\\\/]+#', '', $value) ?? $value;

			// Split into path segments and drop every segment that is only dots or empty.
			// This also covers a bare ".." with no trailing separator, and a leading "/"
			// that would otherwise make the path absolute. Working segment-by-segment
			// (rather than stripping the substrings "../"/"..\\") also closes the
			// overlapping-match bypass ("....//" leaving "../" behind after a single pass).
			$segments = preg_split('#[\\\\/]+#', $value) ?: [];
			$segments = array_filter($segments, static fn(string $segment): bool => trim($segment, '.') !== '');

			return implode('/', $segments);
		}
	}
