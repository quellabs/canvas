<?php

	if (!class_exists('CanvasMysqliStatement')) {
		/**
		 * mysqli_stmt subclass that monitors execute() calls for the inspector.
		 * A real subclass (not a composition wrapper) so legacy code doing
		 * `$stmt instanceof mysqli_stmt`, or passing it to a mysqli_stmt-typed
		 * parameter, keeps working.
		 *
		 * Excluded from PHPStan (see phpstan.neon): bind_param()'s override is
		 * flagged as an incompatible by-ref parameter against mysqli_stmt's
		 * bundled signature, which (verified via ReflectionMethod on PHP
		 * 8.1-8.4) wrongly omits by-ref for that parameter. PHPStan treats
		 * this error category as non-ignorable inline or via baseline.
		 */
		class CanvasMysqliStatement extends mysqli_stmt {
			/** @var string The prepared query, captured for logging */
			private string $query = '';

			/** @var array<int, mixed> */
			private array $boundParams = [];

			/**
			 * Captures the query text before delegating to the real prepare(),
			 * so prepare() keeps mysqli_prepare()'s false-on-failure contract
			 * (the constructor itself cannot return false on a bad query).
			 * @param string $query SQL to prepare
			 * @return bool Success status
			 */
			public function prepare(string $query): bool {
				$this->query = $query;
				return parent::prepare($query);
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
				return parent::bind_param($types, ...$vars);
			}

			/**
			 * Monitored execute method
			 * @param array<int, mixed>|null $params Parameters to bind
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
		}
	}
