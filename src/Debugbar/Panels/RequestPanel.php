<?php
	
	namespace Quellabs\Canvas\Debugbar\Panels;
	
	use Quellabs\Canvas\Debugbar\DebugEventCollector;
	use Quellabs\Canvas\Debugbar\DebugPanelInterface;
	use Quellabs\Canvas\Debugbar\Helpers\RequestExtractor;
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
		 * Returns a JavaScript string that generates the HTML for the panel.
		 * The template includes:
		 * - Helper functions for formatting route parameters and truncating strings
		 * - Route information section
		 * - Request details section
		 * - POST data section (if present)
		 * - Uploaded files section (if present)
		 * - Cookies section (if present)
		 *
		 * @return string JavaScript template code
		 */
		public function getJsTemplate(): string {
			return <<<JS
// Helper function to format route parameters for display
const formatRouteParams = (params) => {
    if (!params || Object.keys(params).length === 0) {
        return 'None';
    }
    return Object.entries(params)
        .map(([key, value]) => `\${key}: \${value}`)
        .join(', ');
};

// Helper function to truncate long strings
const truncate = (str, length) => {
    if (!str) return '';
    return str.length > length ? str.substring(0, length) + '...' : str;
};

// Extract data from the panel data object
const request = data.request;
const route = data.route;

// Generate the complete HTML template
return `
    <div id="panel-request" class="canvas-debug-bar-debug-panel">
        <!-- Route Information Section -->
        <div class="canvas-debug-bar-panel-section">
            <h3>Route Information</h3>
            <div class="canvas-debug-bar-info-grid">
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Controller:</span>
                    <span class="canvas-debug-bar-value">\${route.controller || 'N/A'}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Method:</span>
                    <span class="canvas-debug-bar-value">\${route.method || 'N/A'}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Route Pattern:</span>
                    <span class="canvas-debug-bar-value">\${route.pattern || 'N/A'}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Route Parameters:</span>
                    <span class="canvas-debug-bar-value">\${formatRouteParams(route.parameters)}</span>
                </div>
                <!-- Show legacy file info only if this is a legacy route -->
                \${route.legacy ? `
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Legacy File:</span>
                    <span class="canvas-debug-bar-value">\${route.legacyFile}</span>
                </div>
                ` : ''}
            </div>
        </div>
        
        <!-- Request Details Section -->
        <div class="canvas-debug-bar-panel-section">
            <h3>Request Details</h3>
            <div class="canvas-debug-bar-info-grid">
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">HTTP Method:</span>
                    <span class="canvas-debug-bar-value">\${request.method}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">URI:</span>
                    <span class="canvas-debug-bar-value">\${request.uri}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Full URL:</span>
                    <span class="canvas-debug-bar-value">\${request.url}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Client IP:</span>
                    <span class="canvas-debug-bar-value">\${request.ip}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">User Agent:</span>
                    <span class="canvas-debug-bar-value" title="\${request.userAgent}">\${truncate(request.userAgent, 60)}</span>
                </div>
                <div class="canvas-debug-bar-info-item">
                    <span class="canvas-debug-bar-label">Referer:</span>
                    <span class="canvas-debug-bar-value">\${request.referer || 'None'}</span>
                </div>
            </div>
        </div>

        <!-- POST Data Section (only shown if POST data exists) -->
        \${Object.keys(request.request).length > 0 ? `
        <div class="canvas-debug-bar-panel-section">
            <h3>POST Data</h3>
            <div class="canvas-debug-bar-params-list">
                \${Object.entries(request.request).map(([name, value]) => `
                    <div class="canvas-debug-bar-param-item">
                        <span class="canvas-debug-bar-param-name">\${name}:</span>
                        <span class="canvas-debug-bar-param-value">\${escapeHtml(JSON.stringify(value))}</span>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <!-- Uploaded Files Section (only shown if files were uploaded) -->
        \${Object.keys(request.files).length > 0 ? `
        <div class="canvas-debug-bar-panel-section">
            <h3>Uploaded Files</h3>
            <div class="canvas-debug-bar-files-list">
                \${Object.entries(request.files).map(([name, file]) => `
                    <div class="canvas-debug-bar-file-item \${file.isValid ? 'valid' : 'invalid'}">
                        <!-- File header with name, size, and error indicator -->
                        <div class="canvas-debug-bar-file-header">
                            <span class="canvas-debug-bar-file-name">\${name}</span>
                            <span class="canvas-debug-bar-file-size">\${file.sizeFormatted}</span>
                            \${!file.isValid ? `<span class="canvas-debug-bar-file-error">ERROR</span>` : ''}
                        </div>
                        <!-- Detailed file information -->
                        <div class="canvas-debug-bar-file-details">
                            <div class="canvas-debug-bar-file-detail">
                                <span class="canvas-debug-bar-label">Original Name:</span>
                                <span class="canvas-debug-bar-value">\${escapeHtml(file.originalName || 'N/A')}</span>
                            </div>
                            <div class="canvas-debug-bar-file-detail">
                                <span class="canvas-debug-bar-label">MIME Type:</span>
                                <span class="canvas-debug-bar-value">\${file.mimeType || 'Unknown'}</span>
                            </div>
                            <div class="canvas-debug-bar-file-detail">
                                <span class="canvas-debug-bar-label">Extension:</span>
                                <span class="canvas-debug-bar-value">\${file.extension || 'None'}</span>
                            </div>
                            <!-- Show error message for invalid files -->
                            \${!file.isValid ? `
                            <div class="canvas-debug-bar-file-detail">
                                <span class="canvas-debug-bar-label">Error:</span>
                                <span class="canvas-debug-bar-value canvas-debug-bar-error">\${file.errorMessage}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
        
        <!-- Cookies Section (only shown if cookies exist) -->
        \${Object.keys(request.cookies).length > 0 ? `
        <div class="canvas-debug-bar-panel-section">
            <h3>Cookies</h3>
            <div class="canvas-debug-bar-params-list">
                \${Object.entries(request.cookies).map(([name, value]) => `
                    <div class="canvas-debug-bar-param-item">
                        <span class="canvas-debug-bar-param-name">\${name}:</span>
                        <span class="canvas-debug-bar-param-value">\${escapeHtml(value)}</span>
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
    </div>
`;
JS;
		}
		
		/**
		 * Get the CSS styles for the panel
		 *
		 * Returns CSS rules for styling the request panel including:
		 * - Grid layout for info items
		 * - Styling for parameter lists
		 * - File upload styling with error states
		 * - Responsive design considerations
		 *
		 * @return string CSS stylesheet
		 */
		public function getCss(): string {
			return <<<CSS
/* Grid layout for displaying request information */
.canvas-debug-bar-info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 8px;
}

/* Individual info item styling */
.canvas-debug-bar-info-item {
    display: flex;
    padding: 8px 0;
    border-bottom: 1px solid #e0e0e0;
}

/* Label styling within info items */
.canvas-debug-bar-info-item .canvas-debug-bar-label {
    min-width: 120px;
    color: #666666;
    font-weight: 500;
}

/* Value styling within info items */
.canvas-debug-bar-info-item .canvas-debug-bar-value {
    color: #333333;
    word-break: break-all;
}

/* Container for parameter lists (POST data, cookies) */
.canvas-debug-bar-params-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    max-height: 200px;
    overflow-y: auto;
}

/* Individual parameter item */
.canvas-debug-bar-param-item {
    display: flex;
    padding: 4px 0;
    border-bottom: 1px solid #f0f0f0;
    font-size: 12px;
}

/* Parameter name styling */
.canvas-debug-bar-param-name {
    min-width: 150px;
    color: #666666;
    font-weight: 500;
}

/* Parameter value styling with monospace font */
.canvas-debug-bar-param-value {
    color: #333333;
    word-break: break-all;
    font-family: 'Consolas', 'Monaco', monospace;
}

/* Container for uploaded files list */
.canvas-debug-bar-files-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

/* Individual file item styling */
.canvas-debug-bar-file-item {
    background: #f8f9fa;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 12px;
}

/* Invalid file styling (red border and background) */
.canvas-debug-bar-file-item.invalid {
    border-color: #dc3545;
    background: #f8d7da;
}

/* File header with name, size, and error indicator */
.canvas-debug-bar-file-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
}

/* File name styling */
.canvas-debug-bar-file-name {
    color: #0066cc;
    font-family: 'Consolas', 'Monaco', monospace;
    font-weight: 500;
}

/* File size badge */
.canvas-debug-bar-file-size {
    color: #666666;
    font-size: 11px;
    background: #e9ecef;
    padding: 2px 6px;
    border-radius: 3px;
}

/* Error badge for invalid files */
.canvas-debug-bar-file-error {
    color: white;
    background: #dc3545;
    font-size: 10px;
    font-weight: bold;
    padding: 2px 6px;
    border-radius: 3px;
}

/* Container for file detail items */
.canvas-debug-bar-file-details {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

/* Individual file detail item */
.canvas-debug-bar-file-detail {
    display: flex;
    font-size: 12px;
}

/* Error text styling */
.canvas-debug-bar-error {
    color: #dc3545;
    font-weight: 500;
}
CSS;
		}
	}