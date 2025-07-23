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
	
	if (!function_exists('canvas_mysqli_query')) {
		/**
		 * Monitored version of mysqli_query that logs queries for inspection
		 * @param mysqli $connection The MySQL connection
		 * @param string $query The SQL query to execute
		 * @param int $resultMode Optional result mode (MYSQLI_STORE_RESULT or MYSQLI_USE_RESULT)
		 * @return mysqli_result|bool Query result or false on failure
		 */
		function canvas_mysqli_query(mysqli $connection, string $query, int $resultMode = MYSQLI_STORE_RESULT): mysqli_result|bool {
			// Fetch SignalHub and Signal
			$signalHub = \Quellabs\SignalHub\SignalHubLocator::getInstance();
			$signal = $signalHub->getSignal('debug.objectquel.query');
			
			if ($signal === null) {
				$signal = new \Quellabs\SignalHub\Signal(['array'], 'debug.objectquel.query');
				$signalHub->registerSignal($signal);
			}
			
			// Record query start time for performance monitoring
			$startTime = microtime(true);
			
			// Execute the actual query
			$result = mysqli_query($connection, $query, $resultMode);
			
			// Calculate execution time
			$executionTime = round(microtime(true) - $startTime);
			
			// Log query information for inspector
			$signal->emit([
				'query'             => $query,
				'bound_parameters'  => [],
				'execution_time_ms' => $executionTime,
				'timestamp'         => date('Y-m-d H:i:s'),
				'memory_usage_kb'   => memory_get_usage(true) / 1024,
				'peak_memory_kb'    => memory_get_peak_usage(true) / 1024
			]);
			
			// Return the original result
			return $result;
		}
	}