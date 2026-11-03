<?php

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
