<?php

	// Global array to store headers for Canvas processing
	if (!isset($__canvas_headers)) {
		$__canvas_headers = [];
	}
	
	/**
	 * Canvas replacement for PHP's header() function.
	 * Stores headers in a global array for later processing by LegacyHandler.
	 *
	 * @param string $header The header string to send
	 * @param bool $replace Whether to replace a previous similar header
	 * @param int|null $responseCode Optional HTTP response code
	 * @return void
	 */
	function canvas_header(string $header, bool $replace = true, ?int $responseCode = null): void {
		global $__canvas_headers;
		
		// Create variable if it doesn't exist yet
		if (!isset($__canvas_headers)) {
			$__canvas_headers = [];
		}
		
		// If a response code is provided, add it as a separate Status header
		if ($responseCode !== null) {
			$statusHeader = "Status: {$responseCode}";
			
			// Handle replace logic for status headers
			if ($replace) {
				// Remove any existing Status headers
				$__canvas_headers = array_filter($__canvas_headers, function($h) {
					return !preg_match('/^Status:/i', $h);
				});
			}
			
			$__canvas_headers[] = $statusHeader;
		}
		
		// Handle the main header
		if ($replace) {
			// Extract header name to check for duplicates
			if (preg_match('/^([^:]+):/', $header, $matches)) {
				$headerName = trim($matches[1]);
				
				// Remove existing headers with the same name
				$__canvas_headers = array_filter($__canvas_headers, function($h) use ($headerName) {
					return !preg_match('/^' . preg_quote($headerName, '/') . ':/i', $h);
				});
			}
		}
		
		// Add the new header
		$__canvas_headers[] = $header;
	}