<?php
	
	/**
	 * Polyfill bootstrap file for deprecated PHP functions
	 *
	 * This file provides global function replacements for functions that have been
	 * deprecated or removed in newer PHP versions. It should be loaded early in
	 * the application bootstrap process or via Composer's autoload files.
	 */
	
	use Quellabs\Canvas\Polyfills\Polyfills;
	
	// For PHP 8.2/8.3: Functions exist but are deprecated
	// For PHP 9.0+: Functions don't exist and need to be defined
	
	if (!function_exists('utf8_encode')) {
		/**
		 * Polyfill for utf8_encode() - converts ISO-8859-1 to UTF-8
		 * @param string $data
		 * @return string
		 */
		function utf8_encode(string $data): string {
			return Polyfills::utf8_encode($data);
		}
	}
	
	if (!function_exists('utf8_decode')) {
		/**
		 * Polyfill for utf8_decode() - converts UTF-8 to ISO-8859-1
		 * @param string $data
		 * @return string
		 */
		function utf8_decode(string $data): string {
			return Polyfills::utf8_decode($data);
		}
	}