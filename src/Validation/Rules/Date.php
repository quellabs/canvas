<?php
	
	namespace Quellabs\Canvas\Validation\Rules;
	
	use Quellabs\Canvas\Validation\Foundation\RulesBase;
	
	class Date extends RulesBase {

		/**
		 * Validates that the given value is a recognizable date string.
		 * Empty strings and null are considered valid (use a NotBlank rule to enforce presence).
		 * @param mixed $value
		 * @return bool
		 */
		public function validate(mixed $value): bool {
			if ($value === "" || $value === null) {
				return true;
			}
			
			return $this->dateExtractFormat($value) !== false;
		}
		
		/**
		 * Returns the validation error message.
		 * Uses the custom message if one was provided at construction time,
		 * otherwise falls back to the default.
		 * @return string
		 */
		public function getError(): string {
			if (is_null($this->message)) {
				return "This value is not a valid date.";
			}
			
			return $this->message;
		}
		
		/**
		 * Attempts to detect the date/time format of the given string by matching
		 * it against a set of known patterns. Each pattern is tested against the
		 * original input independently so earlier matches cannot corrupt the string
		 * before later patterns run.
		 * @url https://stackoverflow.com/questions/43873454/identify-date-format-from-a-string-in-php
		 * @param string $date The raw date string to inspect
		 * @return string|bool The detected PHP date format string, or false on failure
		 */
		protected function dateExtractFormat(string $date): bool|string {
			// Apply each pattern to the original input independently so that
			// earlier replacements cannot corrupt the string before later
			// patterns run against it.
			foreach ($this->patterns() as $pattern => $format) {
				$result = preg_replace($pattern, $format, $date);
				
				// preg_replace returns null on a PREG error (e.g. malformed regex
				// or backtrack limit hit) — skip and try remaining patterns.
				if ($result === null) {
					continue;
				}
				
				// If the string changed, this pattern matched the input.
				if ($result !== $date) {
					return $format;
				}
			}
			
			return false;
		}
		
		/**
		 * Returns the map of regex patterns to PHP date format strings used for
		 * format detection. Patterns are applied in order via a single preg_replace
		 * call, so more specific formats (e.g. ISO 8601 with milliseconds) are
		 * listed before more general ones to avoid partial matches shadowing them.
		 * @return array<string, string>
		 */
		protected function patterns(): array {
			return [
				// ISO 8601 with milliseconds: 2024-05-01T13:45:00.000Z
				'/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3,8}Z\b/'     => 'Y-m-d\TH:i:s.u\Z',
				
				// Dash-separated, year first
				'/\b\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2]\d|3[0-1])\b/'     => 'Y-m-d', // 2024-05-01
				'/\b\d{4}-(0[1-9]|[1-2]\d|3[0-1])-(0[1-9]|1[0-2])\b/'     => 'Y-d-m', // 2024-01-05
				
				// Dash-separated, year last (with and without leading zeros on day)
				'/\b([1-9]|[1-2]\d|3[0-1])-([1-9]|1[0-2])-\d{4}\b/'       => 'd-m-Y', // 1-5-2024
				'/\b(0[1-9]|[1-2]\d|3[0-1])-(0[1-9]|1[0-2])-\d{4}\b/'     => 'd-m-Y', // 01-05-2024
				'/\b(0[1-9]|1[0-2])-(0[1-9]|[1-2]\d|3[0-1])-\d{4}\b/'     => 'm-d-Y', // 05-01-2024
				
				// Slash-separated, year first
				'/\b\d{4}\/(0[1-9]|[1-2]\d|3[0-1])\/(0[1-9]|1[0-2])\b/'   => 'Y/d/m', // 2024/01/05
				'/\b\d{4}\/(0[1-9]|1[0-2])\/(0[1-9]|[1-2]\d|3[0-1])\b/'   => 'Y/m/d', // 2024/05/01
				
				// Slash-separated, year last
				'/\b(0[1-9]|[1-2]\d|3[0-1])\/(0[1-9]|1[0-2])\/\d{4}\b/'   => 'd/m/Y', // 01/05/2024
				'/\b(0[1-9]|1[0-2])\/(0[1-9]|[1-2]\d|3[0-1])\/\d{4}\b/'   => 'm/d/Y', // 05/01/2024
				
				// Dot-separated, year first
				'/\b\d{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[1-2]\d|3[0-1])\b/'   => 'Y.m.d', // 2024.05.01
				'/\b\d{4}\.(0[1-9]|[1-2]\d|3[0-1])\.(0[1-9]|1[0-2])\b/'   => 'Y.d.m', // 2024.01.05
				
				// Dot-separated, year last
				'/\b(0[1-9]|[1-2]\d|3[0-1])\.(0[1-9]|1[0-2])\.\d{4}\b/'   => 'd.m.Y', // 01.05.2024
				'/\b(0[1-9]|1[0-2])\.(0[1-9]|[1-2]\d|3[0-1])\.\d{4}\b/'   => 'm.d.Y', // 05.01.2024
				
				// 24-hour time
				'/\b(?:2[0-3]|[01]\d):[0-5]\d(:[0-5]\d)\.\d{3,6}\b/'       => 'H:i:s.u', // 13:45:00.000
				'/\b(?:2[0-3]|[01]\d):[0-5]\d(:[0-5]\d)\b/'                 => 'H:i:s',   // 13:45:00
				'/\b(?:2[0-3]|[01]\d):[0-5]\d\b/'                           => 'H:i',     // 13:45
				
				// 12-hour time
				'/\b(?:1[012]|0\d):[0-5]\d(:[0-5]\d)\.\d{3,6}\b/'           => 'h:i:s.u', // 01:45:00.000
				'/\b(?:1[012]|0\d):[0-5]\d(:[0-5]\d)\b/'                    => 'h:i:s',   // 01:45:00
				'/\b(?:1[012]|0\d):[0-5]\d\b/'                              => 'h:i',     // 01:45
				
				// Millisecond fragment (standalone, e.g. trailing .123)
				'/\.\d{3}\b/'                                                => '.v'
			];
		}
	}