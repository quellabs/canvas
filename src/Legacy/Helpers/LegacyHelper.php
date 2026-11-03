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
				$signal = new \Quellabs\SignalHub\Signal('debug.database.query');
				$signalHub->registerSignal($signal);
			}
			
			return $signal;
		}
	}
	
	// Its own file so phpstan.neon's excludePaths can scope around
	// bind_param()'s unavoidable, PHPStan-unignorable false positive
	// (see that class's docblock) without losing analysis of this file.
	require_once __DIR__ . '/CanvasMysqliStatement.php';
	
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
		 * Monitored version of mysqli_prepare that returns a real mysqli_stmt subclass
		 * @param mysqli $connection The MySQL connection
		 * @param string $query The SQL query to prepare
		 * @return CanvasMysqliStatement|false Prepared statement or false on failure
		 */
		function canvas_mysqli_prepare(mysqli $connection, string $query): CanvasMysqliStatement|false {
			// Constructed without a query, same as mysqli_stmt_init() - preparing
			// happens in the prepare() call below so failure can return false,
			// which the constructor itself is not able to do
			$statement = new CanvasMysqliStatement($connection);

			if (!$statement->prepare($query)) {
				return false;
			}

			return $statement;
		}
	}
	
	if (!class_exists('CanvasPDOStatement')) {
		/**
		 * PDOStatement subclass that monitors execute() calls for the inspector.
		 * A real subclass (not a composition wrapper) so legacy code doing
		 * `$stmt instanceof PDOStatement`, or passing it to a PDOStatement-typed
		 * parameter, keeps working. PDO instantiates it directly via
		 * PDO::ATTR_STATEMENT_CLASS, so the constructor must stay parameterless
		 * and non-public.
		 */
		class CanvasPDOStatement extends PDOStatement {
			/**
			 * @return void
			 */
			protected function __construct() {
			}

			/**
			 * Monitored execute method
			 * @param array<int|string, mixed>|null $params Parameters to bind
			 * @return bool Success status
			 */
			public function execute(?array $params = null): bool {
				// Fetch Signal
				$signal = canvas_fetch_debug_signal();

				// Record query start time for performance monitoring
				$startTime = microtime(true);

				// Execute the actual query
				$result = parent::execute($params);

				// Calculate execution time
				$executionTime = round((microtime(true) - $startTime) * 1000);

				// Log query information for inspector; queryString is PDOStatement's
				// own property, so the original SQL never needs to be passed in
				$signal->emit([
					'driver'            => 'pdo_prepared',
					'query'             => $this->queryString,
					'bound_parameters'  => $params ?? [],
					'execution_time_ms' => $executionTime,
					'timestamp'         => date('Y-m-d H:i:s'),
					'memory_usage_kb'   => memory_get_usage(true) / 1024,
					'peak_memory_kb'    => memory_get_peak_usage(true) / 1024,
				]);

				return $result;
			}
		}
	}
	
	if (!class_exists('CanvasPDO')) {
		/**
		 * PDO subclass that monitors query(), prepare(), and exec() calls for the
		 * inspector. A real subclass (not a composition wrapper) so legacy code
		 * doing `$pdo instanceof PDO`, or passing it to a PDO-typed parameter,
		 * keeps working.
		 */
		class CanvasPDO extends PDO {
			/**
			 * @param string $dsn The Data Source Name
			 * @param string|null $username The username for the connection
			 * @param string|null $password The password for the connection
			 * @param array<int|string, mixed>|null $options Driver-specific connection options
			 */
			public function __construct(string $dsn, ?string $username = null, ?string $password = null, ?array $options = null) {
				parent::__construct($dsn, $username, $password, $options);

				// ATTR_STATEMENT_CLASS makes prepare() return CanvasPDOStatement
				// automatically, so its execute() calls are monitored without
				// overriding prepare() here. Persistent connections reject this
				// attribute outright, so monitoring is skipped for those instead
				// of breaking the connection.
				if (($options[PDO::ATTR_PERSISTENT] ?? false) !== true) {
					$this->setAttribute(PDO::ATTR_STATEMENT_CLASS, [CanvasPDOStatement::class]);
				}
			}

			/**
			 * Monitored query method. PDO::query() executes immediately and never
			 * triggers CanvasPDOStatement::execute(), so logging happens here instead.
			 * @param mixed ...$fetchModeArgs
			 */
			public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): PDOStatement|false {
				$signal = canvas_fetch_debug_signal();
				$startTime = microtime(true);

				if ($fetchMode === null) {
					$result = parent::query($query);
				} else {
					$result = parent::query($query, $fetchMode, ...$fetchModeArgs);
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
			 * Monitored exec method
			 */
			public function exec(string $statement): int|false {
				$signal = canvas_fetch_debug_signal();
				$startTime = microtime(true);

				$result = parent::exec($statement);

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
		}
	}

	if (!function_exists('canvas_create_pdo')) {
		/**
		 * Creates a monitored PDO instance that automatically logs all queries
		 * @param string $dsn The Data Source Name
		 * @param string|null $username The username for the connection
		 * @param string|null $password The password for the connection
		 * @param array<int|string, mixed>|null $options Driver-specific connection options
		 * @return CanvasPDO Monitored PDO instance
		 */
		function canvas_create_pdo(
			string  $dsn,
			?string $username = null,
			?string $password = null,
			?array  $options = null
		): CanvasPDO {
			return new CanvasPDO($dsn, $username, $password, $options);
		}
	}