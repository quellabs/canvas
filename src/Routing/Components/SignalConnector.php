<?php
	
	namespace Quellabs\Canvas\Routing\Components;
	
	use Quellabs\Canvas\SignalHub\SignalProviderInterface;
	use Quellabs\Discover\Discover;
	use Quellabs\Discover\Scanner\ComposerScanner;
	use Quellabs\SignalHub\Signal;
	
	/**
	 * Wires signals to their slots by delegating to all registered signal providers.
	 *
	 * Signal providers are discovered via Composer's extra.signal-hub.providers key.
	 * Each provider implements a connect() method that decides, based on signal name,
	 * whether to attach any slots to the given signal.
	 *
	 * Discovery runs once at construction time since this class is container-managed.
	 */
	class SignalConnector {
		
		/**
		 * @var array Signal provider instances discovered from composer packages
		 */
		private array $connectors;
		
		/**
		 * Discover all signal providers from packages that declare themselves
		 * under the "signal-hub" family in their composer.json extra section.
		 */
		public function __construct() {
			$discover = new Discover();
			$discover->addScanner(new ComposerScanner("signal-hub"));
			$discover->discover();
			
			$this->connectors = array_filter(
				iterator_to_array($discover->getProviders()),
				fn($provider) => $provider instanceof SignalProviderInterface
			);
		}
		
		/**
		 * Wire a set of signals to their slots by passing each signal to every
		 * registered provider. Providers silently ignore signals they don't handle.
		 * @param Signal[] $signals Signals to wire, typically freshly discovered on an object
		 * @return void
		 */
		public function connect(array $signals): void {
			foreach ($signals as $signal) {
				foreach ($this->connectors as $connector) {
					$connector->connect($signal);
				}
			}
		}
	}