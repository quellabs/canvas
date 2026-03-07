<?php
	
	namespace Quellabs\Canvas\SignalHub;
	
	use Quellabs\Contracts\Discovery\ProviderInterface;
	use Quellabs\SignalHub\Signal;
	
	interface SignalProviderInterface extends ProviderInterface {
		
		public function connect(Signal $signal);
		
	}