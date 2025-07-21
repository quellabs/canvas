<?php
	
	namespace Quellabs\Canvas\Debugbar\Panels;
	
	use Quellabs\Canvas\Debugbar\DebugEventCollector;
	use Quellabs\Canvas\Debugbar\DebugPanelInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Debug panel for displaying database query information.
	 *
	 * This panel collects and displays database query events including execution time,
	 * SQL queries, and bound parameters in a formatted debug interface.
	 */
	class QueryPanel implements DebugPanelInterface {

		/** @var array<int, array> Collection of processed query events */
		private array $queries = [];
		
		/** @var float Total execution time for all queries in milliseconds */
		private float $totalTime = 0.0;
		
		/** @var DebugEventCollector Event collector for gathering debug events */
		private DebugEventCollector $collector;
		
		/**
		 * Initialize the QueryPanel with a debug event collector.
		 * @param DebugEventCollector $collector The event collector instance
		 */
		public function __construct(DebugEventCollector $collector) {
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
		 *
		 * This template creates an interactive display showing:
		 * - Individual query execution times
		 * - SQL statements with syntax highlighting
		 * - Parameter tables with proper escaping
		 *
		 * @return string JavaScript template code
		 */
		public function getJsTemplate(): string {
			return <<<'JS'
// Helper function to format query parameters into an HTML table
const formatParameters = (params) => {
    // Handle empty or null parameters
    if (!params || Object.keys(params).length === 0) {
        return '<em>No parameters</em>';
    }
    
    // Generate table rows for each parameter
    const rows = Object.entries(params).map(([key, value]) => `
        <tr>
            <td class="canvas-debug-bar-param-key">${escapeHtml(key)}</td>
            <td class="canvas-debug-bar-param-value">${escapeHtml(JSON.stringify(value))}</td>
        </tr>
    `).join('');
    
    // Return complete parameter table
    return `
        <table class="canvas-debug-bar-params-table">
            <thead>
                <tr>
                    <th>Parameter</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
    `;
};

// Generate HTML for each query with execution details
const queries = data.queries.map(query => `
    <div class="canvas-debug-bar-query-item">
        <div class="canvas-debug-bar-query-header">
            <span class="canvas-debug-bar-query-time">${query.execution_time_ms || 0}ms</span>
        </div>
        <div class="canvas-debug-bar-query-sql">
            <code>${escapeHtml(query.query || 'No query available')}</code>
        </div>
        <div class="canvas-debug-bar-query-params">
            <strong>Parameters:</strong>
            ${formatParameters(query.bound_parameters)}
        </div>
    </div>
`).join('');

// Return complete panel HTML with summary header
return `
    <div class="debug-panel-section">
        <h3>Database Queries (${data.count} queries, ${data.total_time}ms total)</h3>
        <div class="canvas-debug-bar-query-list">
            ${queries}
        </div>
    </div>
`;
JS;
		}
		
		/**
		 * Generate CSS styles for the query panel interface.
		 *
		 * Provides styling for:
		 * - Query list layout and spacing
		 * - Individual query item containers
		 * - Execution time badges
		 * - SQL code formatting
		 * - Parameter tables
		 *
		 * @return string CSS stylesheet
		 */
		public function getCss(): string {
			return <<<'CSS'
/* Main query list container - vertical layout with consistent spacing */
.canvas-debug-bar-query-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

/* Individual query item styling with subtle borders */
.canvas-debug-bar-query-item {
    background: #f8f9fa;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 12px;
}

/* Query header containing execution time and other metadata */
.canvas-debug-bar-query-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
}

/* Execution time badge - green background for quick identification */
.canvas-debug-bar-query-time {
    background: #28a745;
    color: white;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
    min-width: 45px;
    text-align: center;
}

/* SQL code block styling with monospace font and syntax highlighting */
.canvas-debug-bar-query-sql code {
    background: #ffffff;
    color: #d63384;
    padding: 8px;
    border-radius: 3px;
    display: block;
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.4;
    white-space: pre-wrap;
    border: 1px solid #e0e0e0;
    overflow-x: auto;
}

/* Parameter section styling */
.canvas-debug-bar-query-params {
    margin-top: 8px;
    color: #666666;
    font-size: 12px;
}

.canvas-debug-bar-query-params strong {
    display: block;
    margin-bottom: 5px;
    color: #495057;
}

/* Parameter table styling for clean data display */
.canvas-debug-bar-params-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 8px;
    font-size: 12px;
    background: #ffffff;
    border: 1px solid #dee2e6;
}

/* Table header styling */
.canvas-debug-bar-params-table th {
    background: #e9ecef;
    padding: 6px 10px;
    text-align: left;
    font-weight: 600;
    border: 1px solid #dee2e6;
    color: #495057;
}

/* Table cell styling with proper spacing and borders */
.canvas-debug-bar-params-table td {
    padding: 6px 10px;
    border: 1px solid #dee2e6;
    vertical-align: top;
}

/* Parameter key styling for better visual distinction */
.canvas-debug-bar-param-key {
    font-weight: 500;
    color: #495057;
    background: #f8f9fa;
}

/* Parameter value styling with monospace for better readability */
.canvas-debug-bar-param-value {
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    font-size: 11px;
    word-break: break-all;
}
CSS;
		}
	}