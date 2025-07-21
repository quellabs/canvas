<?php
	
	namespace Quellabs\Canvas\Debugbar\Helpers;
	
	use Quellabs\SignalHub\Signal;
	use Quellabs\SignalHub\SignalHub;
	
	/**
	 * This class automatically listens for debug-related signals and stores
	 * their data with timestamps for debugging purposes.
	 */
	class DebugEventCollector {

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
				$signal->connect(function(array $data) use ($name) {
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
		 * Connects to debug signals that already exist in the SignalHub
		 * @param SignalHub $signalHub The signal hub to check for existing signals
		 * @throws \Exception
		 */
		private function connectToExistingSignals(SignalHub $signalHub): void {
			// Connect to the specific debug signal for canvas queries
			// This is needed because the signal might already exist when this collector is created
			$signalHub->getSignal('debug.canvas.query')->connect(function(array $data) {
				// Store the event data with timestamp
				$this->events[] = [
					'signal'    => 'debug.canvas.query',
					'data'      => $data,
					'timestamp' => microtime(true),
				];
			});
		}
	}