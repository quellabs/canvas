<?php

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
