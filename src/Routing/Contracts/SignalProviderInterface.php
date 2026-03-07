<?php
	
	namespace Quellabs\Canvas\Routing\Contracts;
	
	use Quellabs\Contracts\Discovery\ProviderInterface;
	use Quellabs\SignalHub\Signal;
	
	/**
	 * Implemented by classes that wire signals to slots.
	 *
	 * Signal providers are discovered via Composer's extra.signal-hub.providers key.
	 * When a controller is loaded, each discovered signal is passed to every registered
	 * provider. The provider inspects the signal name and connects any relevant slots.
	 *
	 * Providers should silently ignore signals they don't handle — the hub passes every
	 * signal to every provider, so unconditional connections would be a bug.
	 */
	interface SignalProviderInterface extends ProviderInterface {
		
		/**
		 * Connect slots to the given signal if applicable.
		 * Implementations should match on $signal->getName() and ignore unknown signals.
		 * @param Signal $signal The signal to potentially connect slots to
		 */
		public function connect(Signal $signal): void;
	}