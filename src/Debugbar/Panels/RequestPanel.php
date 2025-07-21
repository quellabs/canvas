<?php
	
	namespace Quellabs\Canvas\Debugbar\Panels;
	
	use Quellabs\Canvas\Debugbar\DebugEventCollector;
	use Quellabs\Canvas\Debugbar\Helpers\RequestExtractor;
	use Quellabs\Contracts\Debugbar\DebugPanelInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Request Panel for Canvas Debug Bar
	 *
	 * This panel displays detailed information about HTTP requests including:
	 * - Route information (controller, method, pattern, parameters)
	 * - Request details (HTTP method, URI, IP, user agent)
	 * - POST data and uploaded files
	 * - Cookies
	 *
	 * @package Quellabs\Canvas\Debugbar\Panels
	 */
	class RequestPanel implements DebugPanelInterface {
		
		/** @var DebugEventCollector Event collector for gathering debug information */
		private DebugEventCollector $collector;
		
		/** @var array Route data extracted from canvas events */
		private array $routeData = [];
		
		/**
		 * Constructor
		 *
		 * @param DebugEventCollector $collector The event collector instance
		 */
		public function __construct(DebugEventCollector $collector) {
			$this->collector = $collector;
		}
		
		/**
		 * Get signal patterns this panel listens to
		 *
		 * @return array Array of signal patterns to monitor
		 */
		public function getSignalPatterns(): array {
			return ['debug.canvas.query'];
		}
		
		/**
		 * Process events collected by the debug event collector
		 *
		 * Extracts route data from canvas events and stores it for later use.
		 * Only processes the first matching event found.
		 *
		 * @return void
		 */
		public function processEvents(): void {
			// Get route data from canvas events
			$canvasEvents = $this->collector->getEventsBySignals($this->getSignalPatterns());
			
			foreach ($canvasEvents as $event) {
				// Merge event data with default legacy file field
				$this->routeData = array_merge($event['data'], ['legacyFile' => '']);
				break; // Only process the first event
			}
		}
		
		/**
		 * Get the internal name of this panel
		 *
		 * @return string Panel identifier
		 */
		public function getName(): string {
			return 'request';
		}
		
		/**
		 * Get the display label for the panel tab
		 *
		 * @return string Human-readable panel name
		 */
		public function getTabLabel(): string {
			return 'Request';
		}
		
		/**
		 * Get the icon for the panel tab
		 *
		 * @return string Unicode emoji icon
		 */
		public function getIcon(): string {
			return '🌐';
		}
		
		/**
		 * Get all data needed for panel display
		 *
		 * Combines request data extracted via RequestExtractor with
		 * route data collected from events.
		 *
		 * @param Request $request The Symfony HTTP request object
		 * @return array Associative array containing 'request' and 'route' data
		 */
		public function getData(Request $request): array {
			$requestExtractor = new RequestExtractor($request);
			
			return [
				'request' => $requestExtractor->processRequestData(),
				'route'   => $this->routeData
			];
		}
		
		/**
		 * Get statistical information for the panel
		 *
		 * @return array Statistics to display in the debug bar (e.g., execution time)
		 */
		public function getStats(): array {
			return [
				'time' => round($this->routeData['execution_time_ms'] ?? 0, 2) . 'ms'
			];
		}
		
		/**
		 * Get the JavaScript template for rendering the panel content
		 *
		 * Now uses common components for consistent styling and shows route parameters in a table.
		 *
		 * @return string JavaScript template code
		 */
		public function getJsTemplate(): string {
			return <<<JS
// Extract data from the panel data object
const request = data.request;
const route = data.route;

// Generate the complete HTML template using common components
return `
    <div id="panel-request" class="canvas-debug-bar-debug-panel">
        <!-- Route Information Section -->
        <div class="debug-panel-section">
            <h3>Route Information</h3>
            <div class="canvas-debug-info-grid">
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">Controller:</span>
                    <span class="canvas-debug-value">\${route.controller || 'N/A'}</span>
                </div>
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">Method:</span>
                    <span class="canvas-debug-value">\${route.method || 'N/A'}</span>
                </div>
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">Route Pattern:</span>
                    <span class="canvas-debug-value">\${route.pattern || 'N/A'}</span>
                </div>
                \${route.legacy ? `
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">Legacy File:</span>
                    <span class="canvas-debug-value">\${route.legacyFile}</span>
                </div>
                ` : ''}
            </div>
        </div>
        
        <!-- Request Details Section -->
        <div class="debug-panel-section">
            <h3>Request Details</h3>
            <div class="canvas-debug-info-grid">
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">HTTP Method:</span>
                    <span class="canvas-debug-value">\${request.method}</span>
                </div>
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">URI:</span>
                    <span class="canvas-debug-value">\${request.uri}</span>
                </div>
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">Full URL:</span>
                    <span class="canvas-debug-value">\${request.url}</span>
                </div>
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">Client IP:</span>
                    <span class="canvas-debug-value">\${request.ip}</span>
                </div>
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">User Agent:</span>
                    <span class="canvas-debug-value" title="\${request.userAgent}">\${truncateText(request.userAgent, 60)}</span>
                </div>
                <div class="canvas-debug-info-item">
                    <span class="canvas-debug-label">Referer:</span>
                    <span class="canvas-debug-value">\${request.referer || 'None'}</span>
                </div>
            </div>
        </div>

        <!-- Route Parameters Table -->
        \${route.parameters && Object.keys(route.parameters).length > 0 ? `
        <div class="debug-panel-section">
            <h3>Route parameters</h3>
            \${formatParamsTable(route.parameters, 'No route parameters')}
        </div>
        ` : ''}

        <!-- POST Data Section -->
        \${Object.keys(request.request).length > 0 ? `
        <div class="debug-panel-section">
            <h3>POST Data</h3>
            \${formatParamsTable(request.request, 'No POST data')}
        </div>
        ` : ''}

        <!-- Uploaded Files Section -->
        \${Object.keys(request.files).length > 0 ? `
        <div class="debug-panel-section">
            <h3>Uploaded Files</h3>
            <div class="canvas-debug-item-list">
                \${Object.entries(request.files).map(([name, file]) => `
                    <div class="canvas-debug-item \${file.isValid ? '' : 'error'}">
                        <div class="canvas-debug-item-header">
                            <span class="canvas-debug-text-mono">\${name}</span>
                            <span class="canvas-debug-text-small canvas-debug-text-muted">\${file.sizeFormatted}</span>
                            \${!file.isValid ? `<span class="canvas-debug-status-badge error">ERROR</span>` : ''}
                        </div>
                        <div class="canvas-debug-item-content">
                            <div class="canvas-debug-info-grid">
                                <div class="canvas-debug-info-item">
                                    <span class="canvas-debug-label">Original Name:</span>
                                    <span class="canvas-debug-value">\${escapeHtml(file.originalName || 'N/A')}</span>
                                </div>
                                <div class="canvas-debug-info-item">
                                    <span class="canvas-debug-label">MIME Type:</span>
                                    <span class="canvas-debug-value">\${file.mimeType || 'Unknown'}</span>
                                </div>
                                <div class="canvas-debug-info-item">
                                    <span class="canvas-debug-label">Extension:</span>
                                    <span class="canvas-debug-value">\${file.extension || 'None'}</span>
                                </div>
                                \${!file.isValid ? `
                                <div class="canvas-debug-info-item">
                                    <span class="canvas-debug-label">Error:</span>
                                    <span class="canvas-debug-value canvas-debug-text-error">\${file.errorMessage}</span>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
        
        <!-- Cookies Section -->
        \${Object.keys(request.cookies).length > 0 ? `
        <div class="debug-panel-section">
            <h3>Cookies</h3>
            \${formatParamsTable(request.cookies, 'No cookies')}
        </div>
        ` : ''}
    </div>
`;
JS;
		}
		
		/**
		 * Get the CSS styles for the panel
		 *
		 * Much simpler now since most styling comes from common components.
		 *
		 * @return string CSS stylesheet
		 */
		public function getCss(): string {
			return <<<CSS
/* Error text styling for file upload errors */
.canvas-debug-text-error {
    color: #dc3545;
    font-weight: 500;
}

/* Ensure proper spacing in file upload sections */
.canvas-debug-item-content .canvas-debug-info-grid {
    margin-top: 8px;
}

/* Section headers within panels */
.debug-panel-section h4 {
    margin: 12px 0 8px 0;
    color: #495057;
    font-size: 13px;
    font-weight: 600;
}
CSS;
		}
	}