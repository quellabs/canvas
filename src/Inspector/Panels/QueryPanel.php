<?php
	
	namespace Quellabs\Canvas\Inspector\Panels;
	
	use Quellabs\Canvas\Inspector\EventCollector;
	use Quellabs\Contracts\Inspector\EventCollectorInterface;
	use Quellabs\Contracts\Inspector\InspectorPanelInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Debug panel for displaying database query information.
	 *
	 * This panel collects and displays database query events including execution time,
	 * SQL queries, and bound parameters in a formatted debug interface.
	 */
	class QueryPanel implements InspectorPanelInterface {
		
		/** @var array<int, array<string, mixed>> Collection of processed query events */
		private array $queries = [];
		
		/** @var float Total execution time for all queries in milliseconds */
		private float $totalTime = 0.0;
		
		/**
		 * Process collected events and extract query data.
		 * @return void
		 */
		public function processEvents(EventCollectorInterface $collector): void {
			// Get filtered events from collector based on our signal patterns
			$queryEvents = $collector->getEventsBySignals(['debug.database.query']);
			
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
const queries = data.queries.map((query, qi) => {
    const sqlStatements = query.sql || [];
    const uid = `sql-${qi}`;

    const stepButtons = sqlStatements.length > 1
        ? sqlStatements.map((_, i) => `
            <button onclick="showSqlStep('${uid}', ${i})"
                    id="${uid}-btn-${i}"
                    class="canvas-sql-step-btn ${i === 0 ? 'active' : ''}">${i + 1}</button>
          `).join('')
        : '';

    const sqlBlocks = sqlStatements.length > 0
        ? sqlStatements.map((sql, i) => `
            <pre id="${uid}-sql-${i}" class="canvas-debug-code" style="display:${i === 0 ? 'block' : 'none'}">${escapeHtml(sql)}</pre>
          `).join('')
        : '<em style="font-size:12px;color:#6b7280">No SQL captured</em>';

    const params = Object.entries(query.bound_parameters || {});
    const paramsHtml = params.length > 0
        ? `<div class="canvas-params-table-wrap">
               <table class="canvas-params-table">
                   <thead><tr><th>Parameter</th><th>Value</th></tr></thead>
                   <tbody>
                       ${params.map(([k, v]) => `
                           <tr>
                               <td>${escapeHtml(k)}</td>
                               <td>${escapeHtml(String(v))}</td>
                           </tr>
                       `).join('')}
                   </tbody>
               </table>
           </div>`
        : '';

    return `
        <div>
            <div class="canvas-query-header">
                <div class="canvas-query-header-cell">ObjectQuel</div>
                <div class="canvas-query-header-cell canvas-query-header-cell-right">
                    <span>SQL</span>
                    <div class="canvas-sql-step-buttons">${stepButtons}</div>
                </div>
            </div>
            <div class="canvas-query-body" style="margin-bottom: 12px;">
                <div class="canvas-query-body-left">
                    <pre class="canvas-debug-code">${escapeHtml(query.query || '')}</pre>
                </div>
                <div class="canvas-query-body-right">${sqlBlocks}</div>
            </div>
            ${paramsHtml}
        </div>
    `;
}).join('');

window.showSqlStep = function(uid, index) {
    document.querySelectorAll(`[id^="${uid}-sql-"]`).forEach((el, i) => {
        el.style.display = i === index ? 'block' : 'none';
    });
    document.querySelectorAll(`[id^="${uid}-btn-"]`).forEach((el, i) => {
        el.classList.toggle('active', i === index);
    });
};

return `
    <div class="debug-panel-section">
        <h3>Database queries (${data.count} queries, ${data.total_time}ms total)</h3>
        <div class="canvas-query-list">${queries}</div>
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
.canvas-query-list {
    display: flex;
    flex-direction: column;
    gap: 24px;
}

.canvas-query-header {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    border-bottom: 1px solid #e2e4e9;
    margin-bottom: 8px;
}

.canvas-query-header-cell {
    padding: 0 0 6px;
    font-size: 11px;
    font-weight: 500;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.canvas-query-header-cell-right {
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.canvas-sql-step-buttons {
    display: flex;
    gap: 4px;
}

.canvas-sql-step-btn {
    font-size: 11px;
    padding: 1px 8px;
    border-radius: 4px;
    border: 1px solid #e2e4e9;
    background: transparent;
    color: #6b7280;
    cursor: pointer;
}

.canvas-sql-step-btn.active {
    background: #f3f4f6;
    border-color: #d1d5db;
    color: #111827;
    font-weight: 500;
}

.canvas-query-body {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
}

.canvas-query-body-left {
    padding-right: 16px;
    border-right: 1px solid #e2e4e9;
}

.canvas-query-body-right {
    padding-left: 16px;
}

.canvas-query-body-left .canvas-debug-code,
.canvas-query-body-right .canvas-debug-code {
    border: none;
    background: transparent;
    padding: 0;
}

.canvas-debug-code {
    margin: 0;
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.6;
    color: #111827;
}

.canvas-params-table-wrap {
    border: 1px solid #e2e4e9;
    border-radius: 6px;
    overflow: hidden;
}

.canvas-params-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}

.canvas-params-table thead tr {
    background: #f9fafb;
}

.canvas-params-table th {
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 500;
    color: #6b7280;
    text-align: left;
    border-bottom: 1px solid #e2e4e9;
}

.canvas-params-table th:first-child,
.canvas-params-table td:first-child {
    border-right: 1px solid #e2e4e9;
}

.canvas-params-table td {
    padding: 4px 10px;
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    color: #111827;
}

.canvas-params-table tr + tr td {
    border-top: 1px solid #e2e4e9;
}
CSS;
		}
	}