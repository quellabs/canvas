<?php
	
	namespace Quellabs\Canvas\Polyfills;
	
	/**
	 * Polyfills class provides replacement implementations for deprecated PHP functions
	 *
	 * This class contains static methods that replicate the functionality of PHP functions
	 * that have been deprecated or removed in newer PHP versions, specifically utf8_encode()
	 * and utf8_decode() which were deprecated in PHP 8.2.0.
	 */
	class Polyfills {
		
		/**
		 * Converts a string from ISO-8859-1 encoding to UTF-8
		 * @param string $data The ISO-8859-1 encoded string to convert
		 * @return string The UTF-8 encoded string
		 * @throws \RuntimeException If no suitable encoding conversion function is available
		 */
		static function utf8_encode(string $data): string {
			// Try mb_convert_encoding first (preferred method)
			if (function_exists('mb_convert_encoding')) {
				$result = mb_convert_encoding($data, 'UTF-8', 'ISO-8859-1');
				if ($result !== false) {
					return $result;
				}
			}
			
			// Fallback to iconv if mb_convert_encoding is not available or failed
			if (function_exists('iconv')) {
				$result = iconv('ISO-8859-1', 'UTF-8', $data);
				if ($result !== false) {
					return $result;
				}
			}
			
			// If neither function is available or both failed, throw an exception
			throw new \RuntimeException('No suitable encoding conversion function available');
		}
		
		/**
		 * Converts a string from UTF-8 encoding to ISO-8859-1
		 * @param string $data The UTF-8 encoded string to convert
		 * @return string The ISO-8859-1 encoded string
		 * @throws \RuntimeException If no suitable encoding conversion function is available
		 */
		static public function utf8_decode(string $data): string {
			// Try mb_convert_encoding first (preferred method)
			if (function_exists('mb_convert_encoding')) {
				$result = mb_convert_encoding($data, 'ISO-8859-1', 'UTF-8');
				if ($result !== false) {
					return $result;
				}
			}
			
			// Fallback to iconv if mb_convert_encoding is not available or failed
			if (function_exists('iconv')) {
				$result = iconv('UTF-8', 'ISO-8859-1', $data);
				if ($result !== false) {
					return $result;
				}
			}
			
			// If neither function is available or both failed, throw an exception
			throw new \RuntimeException('No suitable encoding conversion function available');
		}
	}