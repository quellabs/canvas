<?php
	
	namespace Quellabs\Canvas\Inspector;
	
	use Quellabs\Contracts\Inspector\EventCollectorInterface;
	use Quellabs\SignalHub\Signal;
	use Quellabs\SignalHub\SignalHub;
	
	/**
	 * This class automatically listens for debug-related signals and stores
	 * their data with timestamps for debugging purposes.
	 */
	class EventCollector implements EventCollectorInterface {
		
		/**
		 * Array to store collected debug events
		 * Each event contains: signal name, data, and timestamp
		 * @var array
		 */
		private array $events = [];
		
		/**
		 * Constructor - sets up signal listeners for debug events
		 * @param SignalHub $signalHub The signal hub instance to monitor
		 * @throws \Exception
		 */
		public function __construct(SignalHub $signalHub) {
			// Register a listener for when new signals are created
			// This ensures we catch debug signals that are registered after initialization
			$signalHub->signalRegistered()->connect([$this, 'handleNewSignal']);
			
			// Connect to any debug signals that already exist in the hub
			$this->connectToExistingSignals($signalHub);
		}
		
		/**
		 * Handles newly registered signals - automatically connects to debug signals
		 * @param Signal $signal The newly registered signal
		 * @throws \Exception
		 */
		public function handleNewSignal(Signal $signal): void {
			$name = $signal->getName();
			
			// Only connect to signals that start with 'debug.'
			if ($name && str_starts_with($name, 'debug.')) {
				// Connect an anonymous function to capture the signal's data
				$signal->connect(function (array $data) use ($name) {
					// Store the event with signal name, data, and high-precision timestamp
					$this->events[] = [
						'signal'    => $name,
						'data'      => $data,
						'timestamp' => microtime(true), // High precision timestamp for debugging
					];
				});
			}
		}
		
		/**
		 * Returns all collected debug events
		 * @return array Array of events, each containing signal name, data, and timestamp
		 */
		public function getEvents(): array {
			return $this->events;
		}
		
		/**
		 * Filters and returns events that match any of the provided signal patterns
		 * Supports both exact matches and wildcard patterns (using * as wildcard)
		 * @param array $signalPatterns Array of signal names or patterns to match against
		 * @return array Array of matching events, each containing signal name, data, and timestamp
		 */
		public function getEventsBySignals(array $signalPatterns): array {
			return array_values(array_filter($this->events,
				fn($event) => $this->array_some($signalPatterns,
					fn($pattern) => $this->matchesPattern($event['signal'], $pattern)
				)
			));
		}
		
		/**
		 * Convenience method to filter events by a single signal name or pattern
		 * This is a wrapper around getEventsBySignals() for simpler single-pattern usage
		 * @param string $signal The signal name or pattern to match against
		 * @return array Array of matching events, each containing signal name, data, and timestamp
		 */
		public function getEventsBySignal(string $signal): array {
			return $this->getEventsBySignals([$signal]);
		}

		/**
		 * Connects to debug signals that already exist in the SignalHub
		 * @param SignalHub $signalHub The signal hub to check for existing signals
		 * @throws \Exception
		 */
		private function connectToExistingSignals(SignalHub $signalHub): void {
			// Connect to the specific debug signal for canvas queries
			// This is needed because the signal might already exist when this collector is created
			$signalHub->getSignal('debug.canvas.query')->connect(function (array $data) {
				// Store the event data with timestamp
				$this->events[] = [
					'signal'    => 'debug.canvas.query',
					'data'      => $data,
					'timestamp' => microtime(true),
				];
			});
		}
		
		/**
		 * Checks if a signal name matches a given pattern
		 * Supports exact matching and wildcard patterns using asterisk (*) and question mark (?)
		 * @param string $signal The actual signal name to test (e.g., 'debug.cache.hit')
		 * @param string $pattern The pattern to match against:
		 *                        - Exact: 'debug.cache.hit'
		 *                        - Multi-char wildcard: 'debug.cache.*' (matches zero or more chars)
		 *                        - Single-char wildcard: 'debug.cache.h?t' (matches exactly one char)
		 *                        - Combined: 'debug.*.h?t' (combines both wildcard types)
		 * @return bool True if the signal matches the pattern, false otherwise
		 */
		private function matchesPattern(string $signal, string $pattern): bool {
			// Check for exact match first (the most common and fastest case)
			if ($signal === $pattern) {
				return true;
			}

			// If no wildcard found, return false
			if (!str_contains($pattern, '*') && !str_contains($pattern, '?')) {
				return false;
			}
			
			// Handle wildcard patterns (both * and ? wildcards)
			// Convert the wildcard pattern to a regex pattern
			// preg_quote() escapes special regex characters, then we replace wildcards:
			// \* becomes .* (matches zero or more characters)
			// \? becomes .  (matches exactly one character)
			$regexPattern = '/^' . str_replace(['*', '?'], ['.*', '.'], preg_quote($pattern, '/')) . '$/';
			return preg_match($regexPattern, $signal);
		}
		
		/**
		 * Checks if at least one element in the array satisfies the provided callback function.
		 * Similar to JavaScript's Array.prototype.some() method.
		 * @param array $array The array to test
		 * @param callable $callback The callback function to test each element.
		 * @return bool Returns true if at least one element passes the test, false if none do
		 */
		private function array_some(array $array, callable $callback): bool {
			foreach ($array as $item) {
				if ($callback($item)) {
					return true;
				}
			}
			
			return false;
		}
	}