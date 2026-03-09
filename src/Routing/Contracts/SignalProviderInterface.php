<?php
	
	namespace Quellabs\Canvas\Routing\Contracts;
	
	use Quellabs\Contracts\Discovery\ProviderInterface;
	
	/**
	 * Marker interface for signal providers discovered via Composer.
	 *
	 * Classes implementing this interface are discovered via the "signal-hub"
	 * family in composer.json extra. Signal wiring is declared via @ListenTo
	 * annotations.
	 *
	 * @see \Quellabs\Canvas\Annotations\ListenTo
	 */
	interface SignalProviderInterface extends ProviderInterface {
	
	}