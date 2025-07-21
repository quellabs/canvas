<?php
	
	namespace Quellabs\Canvas\Debugbar;
	
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Interface for debug panels in the Canvas debug bar
	 */
	interface DebugPanelInterface {

		/**
		 * Get the unique identifier name for this panel
		 * @return string The panel identifier (e.g., 'queries', 'request', 'performance')
		 */
		public function getName(): string;
		
		/**
		 * Get the display label for the panel tab
		 * @return string Human-readable label shown in the debug bar tab (e.g., 'Database', 'Request')
		 */
		public function getTabLabel(): string;
		
		/**
		 * Get the icon representation for the panel tab
		 * @return string Icon string, typically an emoji or HTML entity (e.g., '🗄️', '🌐', '⚡')
		 */
		public function getIcon(): string;
		
		/**
		 * Get the JavaScript template code for rendering the panel content
		 * @return string JavaScript template code
		 */
		public function getJsTemplate(): string;
		
		/**
		 * Get panel-specific CSS styles
		 * @return string CSS code for styling this panel's content
		 */
		public function getCss(): string;
		
		/**
		 * Get array of signal patterns this panel wants to listen for
		 * @return array Array of signal pattern strings
		 */
		public function getSignalPatterns(): array;
		
		/**
		 * Process collected events and prepare panel data
		 * @return void
		 */
		public function processEvents(): void;
		
		/**
		 * Get the data array to pass to the JavaScript template
		 * @param Request $request The current HTTP request object
		 * @return array Panel data array
		 */
		public function getData(Request $request): array;
		
		/**
		 * Get summary statistics for display in the main debug bar header
		 * @return array Array of stat labels and values (optional)
		 */
		public function getStats(): array;
	}