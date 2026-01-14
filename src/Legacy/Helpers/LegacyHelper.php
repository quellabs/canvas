<?php
	
	// Global array to store headers for Canvas processing
	if (!isset($__canvas_headers)) {
		$__canvas_headers = [];
	}
	
	if (!function_exists('canvas_header')) {
		/**
		 * Canvas replacement for PHP's header() function.
		 * Stores headers in a global array for later processing by LegacyHandler.
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
			// Extract header name to check for duplicates
			if ($replace && preg_match('/^([^:]+):/', $header, $matches)) {
				$headerName = trim($matches[1]);
				
				// Remove existing headers with the same name
				$__canvas_headers = array_filter($__canvas_headers, function ($h) use ($headerName) {
					return !preg_match('/^' . preg_quote($headerName, '/') . ':/i', $h);
				});
			}
			
			// Add the new header
			$__canvas_headers[] = $header;
		}
	}
	
	if (!function_exists('canvas_fetch_debug_signal')) {
		function canvas_fetch_debug_signal(): \Quellabs\SignalHub\Signal {
			$signalHub = \Quellabs\SignalHub\SignalHubLocator::getInstance();
			$signal = $signalHub->getSignal('debug.database.query');
			
			if ($signal === null) {
				$signal = new \Quellabs\SignalHub\Signal(['array'], 'debug.database.query');
				$signalHub->registerSignal($signal);
			}
			
			return $signal;
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
					'driver'            => 'mysqli_prepared',
					'query'             => $this->query,
					'bound_parameters'  => $this->boundParams,
					'execution_time_ms' => $executionTime,
					'timestamp'         => date('Y-m-d H:i:s'),
					'memory_usage_kb'   => memory_get_usage(true) / 1024,
					'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
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
				'driver'            => 'mysqli',
				'query'             => $query,
				'bound_parameters'  => [],
				'execution_time_ms' => $executionTime,
				'timestamp'         => date('Y-m-d H:i:s'),
				'memory_usage_kb'   => memory_get_usage(true) / 1024,
				'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
			]);
			
			// Return the original result
			return $result;
		}
	}
	
	if (!function_exists('canvas_mysqli_prepare')) {
		/**
		 * Monitored version of mysqli_prepare that returns a wrapped statement
		 * @param mysqli $connection The MySQL connection
		 * @param string $query The SQL query to prepare
		 * @return CanvasMysqliStatement|false Wrapped statement or false on failure
		 */
		function canvas_mysqli_prepare(mysqli $connection, string $query): CanvasMysqliStatement|false {
			$statement = mysqli_prepare($connection, $query);
			
			if ($statement === false) {
				return false;
			}
			
			return new CanvasMysqliStatement($statement, $query);
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
					'driver'            => 'pdo_prepared',
					'query'             => $this->query,
					'bound_parameters'  => $params ?? [],
					'execution_time_ms' => $executionTime,
					'timestamp'         => date('Y-m-d H:i:s'),
					'memory_usage_kb'   => memory_get_usage(true) / 1024,
					'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
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
	
	if (!class_exists('CanvasPDO')) {
		/**
		 * Wrapper class for PDO that monitors all query operations
		 * Uses composition instead of inheritance because PDO requires constructor params
		 */
		class CanvasPDO {
			private PDO $pdo;
			
			public function __construct(PDO $pdo) {
				$this->pdo = $pdo;
			}
			
			/**
			 * Monitored query method
			 */
			public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): PDOStatement|false {
				$signal = canvas_fetch_debug_signal();
				$startTime = microtime(true);
				
				if ($fetchMode === null) {
					$result = $this->pdo->query($query);
				} else {
					$result = $this->pdo->query($query, $fetchMode, ...$fetchModeArgs);
				}
				
				$executionTime = round((microtime(true) - $startTime) * 1000);
				
				$signal->emit([
					'driver'            => 'pdo',
					'query'             => $query,
					'bound_parameters'  => [],
					'execution_time_ms' => $executionTime,
					'timestamp'         => date('Y-m-d H:i:s'),
					'memory_usage_kb'   => memory_get_usage(true) / 1024,
					'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
				]);
				
				return $result;
			}
			
			/**
			 * Monitored prepare method
			 */
			public function prepare(string $query, array $options = []): PDOStatement|false {
				$statement = $this->pdo->prepare($query, $options);
				
				if ($statement === false) {
					return false;
				}
				
				return new CanvasPDOStatement($statement, $query);
			}
			
			/**
			 * Monitored exec method
			 */
			public function exec(string $statement): int|false {
				$signal = canvas_fetch_debug_signal();
				$startTime = microtime(true);
				
				$result = $this->pdo->exec($statement);
				
				$executionTime = round((microtime(true) - $startTime) * 1000);
				
				$signal->emit([
					'driver'            => 'pdo',
					'query'             => $statement,
					'bound_parameters'  => [],
					'execution_time_ms' => $executionTime,
					'timestamp'         => date('Y-m-d H:i:s'),
					'memory_usage_kb'   => memory_get_usage(true) / 1024,
					'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
				]);
				
				return $result;
			}
			
			// Forward all other PDO methods
			public function __call(string $method, array $args) {
				return $this->pdo->$method(...$args);
			}
			
			public function __get(string $name) {
				return $this->pdo->$name;
			}
			
			public function __set(string $name, $value) {
				$this->pdo->$name = $value;
			}
		}
	}
	
	if (!function_exists('canvas_create_pdo')) {
		/**
		 * Creates a monitored PDO instance that automatically logs all queries
		 * @param string $dsn The Data Source Name
		 * @param string|null $username The username for the connection
		 * @param string|null $password The password for the connection
		 * @param array|null $options Driver-specific connection options
		 * @return CanvasPDO Monitored PDO instance
		 */
		function canvas_create_pdo(
			string  $dsn,
			?string $username = null,
			?string $password = null,
			?array  $options = null
		): CanvasPDO {
			$pdo = new PDO($dsn, $username, $password, $options);
			return new CanvasPDO($pdo);
		}
	}