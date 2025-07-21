<?php
	
	namespace Quellabs\Canvas\Inspector\Panels;
	
	use Quellabs\Canvas\Inspector\EventCollector;
	use Quellabs\Contracts\Inspector\InspectorPanelInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Debug panel for displaying database query information.
	 *
	 * This panel collects and displays database query events including execution time,
	 * SQL queries, and bound parameters in a formatted debug interface.
	 */
	class QueryPanel implements InspectorPanelInterface {
		
		/** @var array<int, array> Collection of processed query events */
		private array $queries = [];
		
		/** @var float Total execution time for all queries in milliseconds */
		private float $totalTime = 0.0;
		
		/** @var EventCollector Event collector for gathering debug events */
		private EventCollector $collector;
		
		/**
		 * Initialize the QueryPanel with a debug event collector.
		 * @param EventCollector $collector The event collector instance
		 */
		public function __construct(EventCollector $collector) {
			$this->collector = $collector;
		}
		
		/**
		 * Define which event signals this panel should listen for.
		 * @return array<string> Array of signal patterns to match
		 */
		public function getSignalPatterns(): array {
			return ['debug.objectquel.query'];
		}
		
		/**
		 * Process collected events and extract query data.
		 * @return void
		 */
		public function processEvents(): void {
			// Get filtered events from collector based on our signal patterns
			$queryEvents = $this->collector->getEventsBySignals($this->getSignalPatterns());
			
			foreach ($queryEvents as $event) {
				// Store the complete event data for later display
				$this->queries[] = $event['data'];
				
				// Accumulate total execution time (default to 0 if not set)
				$this->totalTime += $event['data']['execution_time_ms'] ?? 0.0;
			}
		}
		
		/**
		 * Get the internal name identifier for this panel.
		 * @return string Panel identifier
		 */
		public function getName(): string {
			return 'queries';
		}
		
		/**
		 * Get the display label for the debug bar tab.
		 * @return string Tab label with query count
		 */
		public function getTabLabel(): string {
			$count = count($this->queries);
			return "Database ({$count})";
		}
		
		/**
		 * Get the icon representation for this panel.
		 * @return string Emoji icon for database operations
		 */
		public function getIcon(): string {
			return '🗄️';
		}
		
		/**
		 * Prepare data for rendering in the debug interface.
		 * @param Request $request Current HTTP request (unused but required by interface)
		 * @return array<string, mixed> Formatted data for template rendering
		 */
		public function getData(Request $request): array {
			return [
				'queries'    => $this->queries,
				'total_time' => round($this->totalTime, 2),
				'count'      => count($this->queries)
			];
		}
		
		/**
		 * Get summary statistics for quick overview.
		 * @return array<string, string> Key-value pairs of statistics
		 */
		public function getStats(): array {
			return [
				'query_time'  => round($this->totalTime, 2) . 'ms',
				'query_count' => (string)count($this->queries)
			];
		}
		
		/**
		 * Generate JavaScript template for rendering query data in the browser.
		 * @return string JavaScript template code
		 */
		public function getJsTemplate(): string {
			return <<<'JS'
// Generate HTML for each query using common components
const queries = data.queries.map(query => `
    <div class="canvas-debug-item">
        <div class="canvas-debug-item-header">
            ${formatTimeBadge(query.execution_time_ms || 0)}
        </div>
        <div class="canvas-debug-item-content">
            <div class="canvas-debug-mb-2">
                <strong>Query:</strong>
                <code class="canvas-debug-code">${escapeHtml(query.query || 'No query available')}</code>
            </div>
            <div>
                <strong>Parameters:</strong>
                ${formatParamsTable(query.bound_parameters, 'No parameters')}
            </div>
        </div>
    </div>
`).join('');

// Return complete panel HTML with summary header
return `
    <div class="debug-panel-section">
        <h3>Database Queries (${data.count} queries, ${data.total_time}ms total)</h3>
        <div class="canvas-debug-item-list">
            ${queries}
        </div>
    </div>
`;
JS;
		}
		
		/**
		 * Generate CSS styles for the query panel interface.
		 * @return string CSS stylesheet
		 */
		public function getCss(): string {
			return <<<'CSS'
/* Override code block styling for ObjectQuel syntax highlighting */
.canvas-debug-item .canvas-debug-code {
    background: #f8f9fa;
    color: #d63384;
    border: 1px solid #e9ecef;
    margin-top: 4px;
}

/* Ensure proper spacing for query content */
.canvas-debug-item-content > div {
    margin-bottom: 8px;
}

.canvas-debug-item-content > div:last-child {
    margin-bottom: 0;
}
CSS;
		}
	}