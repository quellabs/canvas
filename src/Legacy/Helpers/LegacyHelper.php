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
		
		// If a response code is provided, add it as a separate Status header
		if ($responseCode !== null) {
			$statusHeader = "Status: {$responseCode}";
			
			// Handle replace logic for status headers
			if ($replace) {
				// Remove any existing Status headers
				$__canvas_headers = array_filter($__canvas_headers, function ($h) {
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
				$__canvas_headers = array_filter($__canvas_headers, function ($h) use ($headerName) {
					return !preg_match('/^' . preg_quote($headerName, '/') . ':/i', $h);
				});
			}
		}
		
		// Add the new header
		$__canvas_headers[] = $header;
	}
	
	if (!function_exists('canvas_fetch_debug_signal')) {
		function canvas_fetch_debug_signal(): \Quellabs\SignalHub\Signal {
			$signalHub = \Quellabs\SignalHub\SignalHubLocator::getInstance();
			$signal = $signalHub->getSignal('debug.objectquel.query');
			
			if ($signal === null) {
				$signal = new \Quellabs\SignalHub\Signal(['array'], 'debug.objectquel.query');
				$signalHub->registerSignal($signal);
			}
			
			return $signal;
		}
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
			// Fetch Signal
			$signal = canvas_fetch_debug_signal();
			
			// Record query start time for performance monitoring
			$startTime = microtime(true);
			
			// Execute the actual query
			$result = mysqli_query($connection, $query, $resultMode);
			
			// Calculate execution time
			$executionTime = round((microtime(true) - $startTime) * 1000); // Convert to milliseconds
			
			// Log query information for inspector
			$signal->emit([
				'query'             => $query,
				'bound_parameters'  => [],
				'execution_time_ms' => $executionTime,
				'timestamp'         => date('Y-m-d H:i:s'),
				'memory_usage_kb'   => memory_get_usage(true) / 1024,
				'peak_memory_kb' => memory_get_peak_usage(true) / 1024,
				'driver'         => 'mysqli'
			]);
			
			// Return the original result
			return $result;
		}
	}
	
	if (!function_exists('canvas_pdo_query')) {
		/**
		 * Monitored version of PDO::query that logs queries for inspection
		 * @param PDO $pdo The PDO connection
		 * @param string $query The SQL query to execute
		 * @return PDOStatement|false Query result or false on failure
		 */
		function canvas_pdo_query(PDO $pdo, string $query): PDOStatement|false {
			// Fetch Signal
			$signal = canvas_fetch_debug_signal();
			
			// Record query start time for performance monitoring
			$startTime = microtime(true);
			
			// Execute the actual query
			$result = $pdo->query($query);
			
			// Calculate execution time
			$executionTime = round((microtime(true) - $startTime) * 1000);
			
			// Log query information for inspector
			$signal->emit([
				'query'             => $query,
				'bound_parameters'  => [],
				'execution_time_ms' => $executionTime,
				'timestamp'         => date('Y-m-d H:i:s'),
				'memory_usage_kb'   => memory_get_usage(true) / 1024,
				'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
				'driver'            => 'pdo'
			]);
			
			// Return the original result
			return $result;
		}
	}
	
	if (!function_exists('canvas_pdo_prepare')) {
		/**
		 * Monitored version of PDO::prepare that returns a wrapped PDOStatement
		 * @param PDO $pdo The PDO connection
		 * @param string $query The SQL query to prepare
		 * @return CanvasPDOStatement|false Wrapped statement or false on failure
		 */
		function canvas_pdo_prepare(PDO $pdo, string $query): CanvasPDOStatement|false {
			$statement = $pdo->prepare($query);
			
			if ($statement === false) {
				return false;
			}
			
			// Return wrapped statement that will monitor execute() calls
			return new CanvasPDOStatement($statement, $query);
		}
	}
	
	if (!class_exists('CanvasMysqliStatement')) {
		/**
		 * Wrapper class for mysqli_stmt that monitors execute() calls
		 */
		class CanvasMysqliStatement {
			private mysqli_stmt $statement;
			private string $query;
			private array $boundParams = [];
			
			public function __construct(mysqli_stmt $statement, string $query) {
				$this->statement = $statement;
				$this->query = $query;
			}
			
			/**
			 * Monitored bind_param method - captures parameters for logging
			 * @param string $types Parameter types
			 * @param mixed ...$vars Variables to bind
			 * @return bool Success status
			 */
			public function bind_param(string $types, &...$vars): bool {
				// Store bound parameters for logging (by value to avoid reference issues)
				$this->boundParams = [];
				foreach ($vars as $var) {
					$this->boundParams[] = $var;
				}
				
				// Call original bind_param
				return $this->statement->bind_param($types, ...$vars);
			}
			
			/**
			 * Monitored execute method
			 * @return bool Success status
			 */
			public function execute(): bool {
				// Fetch Signal
				$signal = canvas_fetch_debug_signal();
				
				// Record query start time for performance monitoring
				$startTime = microtime(true);
				
				// Execute the actual query
				$result = $this->statement->execute();
				
				// Calculate execution time
				$executionTime = round((microtime(true) - $startTime) * 1000);
				
				// Log query information for inspector
				$signal->emit([
					'query'             => $this->query,
					'bound_parameters'  => $this->boundParams,
					'execution_time_ms' => $executionTime,
					'timestamp'         => date('Y-m-d H:i:s'),
					'memory_usage_kb'   => memory_get_usage(true) / 1024,
					'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
					'driver'            => 'mysqli_prepared'
				]);
				
				return $result;
			}
			
			// Delegate all other method calls to the original mysqli_stmt
			public function __call(string $method, array $args) {
				return $this->statement->$method(...$args);
			}
			
			// Delegate property access to the original mysqli_stmt
			public function __get(string $name) {
				return $this->statement->$name;
			}
			
			public function __set(string $name, $value) {
				$this->statement->$name = $value;
			}
		}
	}
	
	if (!class_exists('CanvasPDOStatement')) {
		/**
		 * Wrapper class for PDOStatement that monitors execute() calls
		 */
		class CanvasPDOStatement {
			private PDOStatement $statement;
			private string $query;
			
			public function __construct(PDOStatement $statement, string $query) {
				$this->statement = $statement;
				$this->query = $query;
			}
			
			/**
			 * Monitored execute method
			 * @param array|null $params Parameters to bind
			 * @return bool Success status
			 */
			public function execute(?array $params = null): bool {
				// Fetch Signal
				$signal = canvas_fetch_debug_signal();
				
				// Record query start time for performance monitoring
				$startTime = microtime(true);
				
				// Execute the actual query
				$result = $this->statement->execute($params);
				
				// Calculate execution time
				$executionTime = round((microtime(true) - $startTime) * 1000);
				
				// Log query information for inspector
				$signal->emit([
					'query'             => $this->query,
					'bound_parameters'  => $params ?? [],
					'execution_time_ms' => $executionTime,
					'timestamp'         => date('Y-m-d H:i:s'),
					'memory_usage_kb'   => memory_get_usage(true) / 1024,
					'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
					'driver'            => 'pdo_prepared'
				]);
				
				return $result;
			}
			
			// Delegate all other method calls to the original PDOStatement
			public function __call(string $method, array $args) {
				return $this->statement->$method(...$args);
			}
			
			// Delegate property access to the original PDOStatement
			public function __get(string $name) {
				return $this->statement->$name;
			}
			
			public function __set(string $name, $value) {
				$this->statement->$name = $value;
			}
		}
	}