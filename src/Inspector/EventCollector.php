<?php
	
	namespace Quellabs\Canvas\Inspector;
	
	use Quellabs\Contracts\Inspector\EventCollectorInterface;
	use Quellabs\SignalHub\Signal;
	use Quellabs\SignalHub\SignalHub;
	use Quellabs\SignalHub\Slot;
	
	/**
	 * This class automatically listens for debug-related signals and stores
	 * their data with timestamps for debugging purposes.
	 */
	class EventCollector implements EventCollectorInterface {
		
		/**
		 * Array to store collected debug events
		 * Each event contains: signal name, data, and timestamp
		 * @var array<array{signal: string, data: array<mixed>, timestamp: float}>
		 */
		private array $events = [];
		
		/**
		 * Slot for the signalRegistered meta-signal on the hub.
		 * Stored as a property to keep the Slot alive for the lifetime of this object.
		 * @var Slot
		 */
		private Slot $handleNewSignalSlot;
		
		/**
		 * Slot for the debug.canvas.query signal, if it existed at construction time.
		 * Stored as a property to keep the Slot alive for the lifetime of this object.
		 * @var Slot|null
		 */
		private ?Slot $debugCanvasQuerySlot = null;
		
		/**
		 * Slots created dynamically in handleNewSignal() for debug signals registered
		 * after construction. Never read — exists solely to hold strong references so
		 * Slots are not GC'd after connect() returns. Signal owns Slots strongly too,
		 * but only after connect() is called; this array guards the gap before that.
		 * @var Slot[]
		 * @phpstan-ignore property.onlyWritten
		 */
		private array $dynamicSlots = [];
		
		/**
		 * Constructor - sets up signal listeners for debug events
		 * @param SignalHub $signalHub The signal hub instance to monitor
		 */
		public function __construct(SignalHub $signalHub) {
			// Register a listener for when new signals are created.
			// This ensures we catch debug signals that are registered after initialization.
			$this->handleNewSignalSlot = new Slot([$this, 'handleNewSignal']);
			$signalHub->signalRegistered()->connect($this->handleNewSignalSlot);
			
			// Connect to any debug signals that already exist in the hub
			$this->connectToCanvasQuerySignal($signalHub);
		}
		
		/**
		 * Handles newly registered signals - automatically connects to debug signals.
		 * @param Signal $signal The newly registered signal
		 */
		public function handleNewSignal(Signal $signal): void {
			$name = $signal->getName();
			
			// Only connect to signals that start with 'debug.'
			if (!$name || !str_starts_with($name, 'debug.')) {
				return;
			}
			
			// Create a Slot for this signal and store a strong reference in $dynamicSlots.
			// Signal will also hold a strong reference after connect(), but we store it
			// here too to make the ownership explicit and guard against any future refactor
			// that might change when connect() is called.
			$slot = new Slot(function (array $data) use ($name): void {
				$this->events[] = [
					'signal'    => $name,
					'data'      => $data,
					'timestamp' => microtime(true),
				];
			});
			
			$this->dynamicSlots[] = $slot;
			$signal->connect($slot);
		}
		
		/**
		 * Returns all collected debug events
		 * @return array<array{signal: string, data: array<mixed>, timestamp: float}>
		 */
		public function getEvents(): array {
			return $this->events;
		}
		
		/**
		 * Filters and returns events that match any of the provided signal patterns.
		 * Supports both exact matches and wildcard patterns (using * and ? as wildcards).
		 * @param array<string> $signalPatterns Array of signal names or patterns to match against
		 * @return array<array{signal: string, data: array<mixed>, timestamp: float}>
		 */
		public function getEventsBySignals(array $signalPatterns): array {
			return array_values(array_filter($this->events,
				fn($event) => $this->array_some($signalPatterns,
					fn($pattern) => $this->matchesPattern($event['signal'], $pattern)
				)
			));
		}
		
		/**
		 * Convenience method to filter events by a single signal name or pattern.
		 * This is a wrapper around getEventsBySignals() for simpler single-pattern usage.
		 * @param string $signal The signal name or pattern to match against
		 * @return array<array{signal: string, data: array<mixed>, timestamp: float}>
		 */
		public function getEventsBySignal(string $signal): array {
			return $this->getEventsBySignals([$signal]);
		}
		
		/**
		 * Connects to the debug.canvas.query signal if it already exists in the hub.
		 * @param SignalHub $signalHub The signal hub to check for existing signals
		 */
		private function connectToCanvasQuerySignal(SignalHub $signalHub): void {
			$signal = $signalHub->getSignal('debug.canvas.query');
			
			if (!$signal) {
				return;
			}
			
			$this->debugCanvasQuerySlot = new Slot(function (array $data): void {
				$this->events[] = [
					'signal'    => 'debug.canvas.query',
					'data'      => $data,
					'timestamp' => microtime(true),
				];
			});
			
			$signal->connect($this->debugCanvasQuerySlot);
		}
		
		/**
		 * Checks if a signal name matches a given pattern.
		 * Supports exact matching and wildcard patterns using asterisk (*) and question mark (?).
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
			
			// If no wildcard characters present, pattern cannot match
			if (!str_contains($pattern, '*') && !str_contains($pattern, '?')) {
				return false;
			}
			
			// Convert the wildcard pattern to a regex pattern.
			// preg_quote() escapes special regex characters, then we restore wildcards:
			// \* becomes .* (matches zero or more characters)
			// \? becomes .  (matches exactly one character)
			$regexPattern = '/^' . str_replace(['\\*', '\\?'], ['.*', '.'], preg_quote($pattern, '/')) . '$/';
			return (bool)preg_match($regexPattern, $signal);
		}
		
		/**
		 * Checks if at least one element in the array satisfies the provided callback.
		 * Similar to JavaScript's Array.prototype.some() method.
		 * @param array<mixed> $array The array to test
		 * @param callable $callback The callback function to test each element
		 * @return bool True if at least one element passes the test, false otherwise
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