<?php

	namespace Quellabs\Canvas\Sanitization\Rules;

	use Quellabs\Canvas\Sanitization\Contracts\SanitizationRuleInterface;

	/**
	 * This class implements a sanitization rule that removes HTML and XML tags
	 * from string values, with optional support for preserving specific allowed tags.
	 * Non-string values are returned unchanged.
	 */
	class StripTags implements SanitizationRuleInterface {

		/**
		 * @var array<string> URL schemes allowed in a surviving href attribute
		 */
		private const array SAFE_HREF_SCHEMES = ['http', 'https', 'mailto', 'tel'];

		/**
		 * @var array<string> Array of HTML tag names that should be preserved
		 */
		private array $allowedTags;

		/**
		 * Constructor for StripTags sanitization rule.
		 * @param array<string> $allowedTags Array of HTML tag names that should be preserved
		 */
		public function __construct(array $allowedTags = []) {
			$this->allowedTags = $allowedTags;
		}

		/**
		 * Sanitize the given value by removing HTML/XML tags.
		 * @param mixed $value The value to sanitize
		 * @return mixed The sanitized value (string with tags removed, or original value if not a string)
		 */
		public function sanitize(mixed $value): mixed {
			// Only process string values - other types are returned as-is
			if (!is_string($value)) {
				return $value;
			}

			// If no allowed tags specified, strip all tags
			if (empty($this->allowedTags)) {
				return strip_tags($value);
			}

			// Build allowed tags string in format required by strip_tags()
			// Converts ['p', 'br'] to '<p><br>'
			$stripped = strip_tags($value, $this->transformAllowedTags($this->allowedTags));

			// strip_tags() only filters tag names; it leaves every attribute on an
			// allowed tag untouched, so "<a href=javascript:...  onclick=...>" survives
			// intact. Strip every attribute from the surviving tags except a safe href,
			// to close that XSS vector while still letting a real link through.
			return $this->stripAttributes($stripped);
		}

		/**
		 * Build allowed tags string in format required by strip_tags()
		 * Converts ['p', 'br'] to '<p><br>'
		 * @param array<string> $tags
		 * @return string
		 */
		private function transformAllowedTags(array $tags): string {
			return '<' . implode('><', $tags) . '>';
		}

		/**
		 * Removes every attribute from tags, keeping only the tag name, the closing
		 * slash, and - if present and safe - the href attribute.
		 * @param string $value
		 * @return string
		 */
		private function stripAttributes(string $value): string {
			return preg_replace_callback('#<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>#', function (array $matches): string {
				// Closing tags never carry attributes
				if ($matches[1] !== '') {
					return "</{$matches[2]}>";
				}

				$href = $this->extractSafeHref($matches[3]);

				if ($href === null) {
					return "<{$matches[2]}>";
				}

				// Re-quote with double quotes regardless of the original quoting, and
				// escape any literal double quote in the value so it can't break out
				// of the attribute it is placed back into.
				return "<{$matches[2]} href=\"" . str_replace('"', '&quot;', $href) . '">';
			}, $value) ?? $value;
		}

		/**
		 * Extracts a tag's href attribute value if present and its URL scheme is safe.
		 * @param string $attributes Raw attribute text from a tag, e.g. ' href="x" onclick="y"'
		 * @return string|null The href value, or null if absent or unsafe
		 */
		private function extractSafeHref(string $attributes): ?string {
			// Quoted value: capture the quote character and read up to its matching
			// close, so a single- and double-quoted value are both handled by one
			// pattern without relying on alternation group numbering.
			if (preg_match('/\bhref\s*=\s*(["\'])((?:(?!\1).)*)\1/i', $attributes, $matches)) {
				$value = $matches[2];
			} elseif (preg_match('/\bhref\s*=\s*([^\s"\'>]+)/i', $attributes, $matches)) {
				$value = $matches[1];
			} else {
				return null;
			}

			return $this->isSafeHref($value) ? $value : null;
		}

		/**
		 * Checks whether a URL's scheme is safe for navigation. A browser strips
		 * tab/newline/CR characters and decodes HTML entities before reading a URL's
		 * scheme, so a payload like "jav&#09;ascript:alert(1)" can hide a dangerous
		 * scheme from a naive string check - normalize the same way before checking.
		 * @param string $value
		 * @return bool
		 */
		private function isSafeHref(string $value): bool {
			$normalized = html_entity_decode($value, ENT_QUOTES | ENT_HTML5);
			$normalized = str_replace(["\t", "\n", "\r"], '', $normalized);
			$normalized = trim($normalized);

			// No scheme at all (relative path, fragment, query-only) is safe - there is nothing to execute
			if (!preg_match('/^([a-zA-Z][a-zA-Z0-9+.-]*):/', $normalized, $schemeMatch)) {
				return true;
			}

			return in_array(strtolower($schemeMatch[1]), self::SAFE_HREF_SCHEMES, true);
		}
	}
