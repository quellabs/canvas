<?php
	
	namespace Quellabs\Canvas\Tracking;
	
	use Quellabs\SignalHub\Signal;
	use Quellabs\Canvas\AOP\Contracts\RequestAspectInterface;
	use Quellabs\Canvas\Routing\Contracts\MethodContextInterface;
	
	class TrackingParamsAspect implements RequestAspectInterface {
		
		/**
		 * UTM parameter names to extract from the request
		 */
		private const array UTM_PARAMS = [
			'utm_source',
			'utm_medium',
			'utm_campaign',
			'utm_term',
			'utm_content',
		];
		
		/**
		 * Emitted when UTM tracking parameters are found in the request.
		 * Receives array<string, string> of found parameters as its argument.
		 */
		public Signal $trackingParamsReceived;
		
		/**
		 * TrackingParamsAspect constructor
		 */
		public function __construct() {
			$this->trackingParamsReceived = new Signal('tracking_params_received');
		}
		
		/**
		 * Extract UTM parameters from the request and emit them as a signal
		 * @param MethodContextInterface $context
		 * @return void
		 */
		public function transformRequest(MethodContextInterface $context): void {
			$params = [];
			
			foreach (self::UTM_PARAMS as $param) {
				$value = $context->getRequest()->query->get($param);
				
				if ($value !== null && $value !== '') {
					$params[$param] = $value;
				}
			}
			
			// Only emit if at least one UTM param was present
			if (!empty($params)) {
				$this->trackingParamsReceived->emit($params);
			}
		}
	}