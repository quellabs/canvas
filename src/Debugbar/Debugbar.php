<?php
	
	namespace Quellabs\Canvas\Debugbar;
	
	use Quellabs\SignalHub\SignalHub;
	use Symfony\Component\HttpFoundation\Request;
	use Symfony\Component\HttpFoundation\Response;
	
	class Debugbar {
		
		private DebugDataProcessor $dataProcessor;
		
		/**
		 * Debugbar constructor
		 * @param DebugEventCollector $collector
		 */
		public function __construct(DebugEventCollector $collector) {
			$this->dataProcessor = new DebugDataProcessor($collector);
		}
		
		/**
		 * Inject the debugbar in the response
		 * @param Request $request
		 * @param Response $response
		 * @return void
		 */
		public function inject(Request $request, Response $response): void {
			$content = $response->getContent();
			$bodyPos = $this->getEndOfBodyPosition($content);
			
			if ($bodyPos !== false) {
				$newContent = substr($content, 0, $bodyPos) . $this->getHtml($request) . substr($content, $bodyPos);
				$response->setContent($newContent);
			}
		}
		
		private function getHtml(Request $request): string {
			return <<<BODY
<!-- Canvas Debug Bar -->
<div id="canvas-debug-bar" class="canvas-debug-bar minimized">
    <div class="canvas-debug-bar-debug-header" onclick="CanvasDebugBar.toggle()">
        <div class="canvas-debug-bar-debug-logo">Canvas Debug</div>
        <div class="canvas-debug-bar-debug-stats" id="debug-stats">
            <!-- JS will populate this -->
        </div>
    </div>
    
    <div class="canvas-debug-bar-debug-content">
        <div class="canvas-debug-bar-debug-tabs" id="debug-tabs">
            <!-- JS will populate tabs -->
        </div>
        
        <div class="canvas-debug-bar-debug-panels" id="debug-panels">
            <!-- JS will populate panels -->
        </div>
    </div>
</div>

<style>
    {$this->getCss()}
</style>

<script>
    {$this->getJs()}
</script>

<script>
    {$this->getDataScript($request)}
</script>
BODY;
		}
		
		/**
		 * Debugbar CSS
		 * @return string
		 */
		private function getCss(): string {
			return <<<CSS
        .canvas-debug-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #ffffff;
            color: #333333;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 13px;
            border-top: 1px solid #e0e0e0;
            box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
            z-index: 999999;
            transition: all 0.3s ease;
            max-height: 80vh;
            overflow: hidden;
        }

        .canvas-debug-bar.minimized {
            max-height: 40px;
        }

        .canvas-debug-bar.minimized .canvas-debug-bar-debug-content {
            display: none;
        }

        /* Debug Header */
        .canvas-debug-bar .canvas-debug-bar-debug-header {
            display: flex;
            align-items: center;
            padding: 10px 16px;
            background: #f8f9fa;
            border-bottom: 1px solid #e0e0e0;
            cursor: pointer;
            user-select: none;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-header:hover {
            background: #f0f0f0;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-logo {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 600;
            color: #0066cc;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-stats {
            display: flex;
            gap: 20px;
            margin-left: auto;
            margin-right: 20px;
        }

        .canvas-debug-bar .canvas-debug-bar-stat {
            display: flex;
            gap: 4px;
        }

        .canvas-debug-bar .canvas-debug-bar-stat-label {
            color: #666666;
        }

        .canvas-debug-bar .canvas-debug-bar-stat-value {
            color: #0066cc;
            font-weight: 500;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-toggle {
            transition: transform 0.3s ease;
        }

        .canvas-debug-bar:not(.minimized) .canvas-debug-bar-debug-toggle {
            transform: rotate(180deg);
        }

        /* Debug Content */
        .canvas-debug-bar .canvas-debug-bar-debug-content {
            display: flex;
            flex-direction: column;
            height: 400px;
        }

        /* Tabs */
        .canvas-debug-bar .canvas-debug-bar-debug-tabs {
            display: flex;
            background: #f8f9fa;
            border-bottom: 1px solid #e0e0e0;
            overflow-x: auto;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-tab {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 12px 16px;
            background: none;
            border: none;
            color: #666666;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.2s ease;
            font-size: 13px;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-tab:hover {
            background: #e9ecef;
            color: #333333;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-tab.active {
            background: #ffffff;
            color: #0066cc;
            border-bottom: 2px solid #0066cc;
        }

        /* Panels */
        .canvas-debug-bar .canvas-debug-bar-debug-panels {
            flex: 1;
            overflow: hidden;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-panel {
            display: none;
            height: 100%;
            overflow-y: auto;
            padding: 16px;
            background: #ffffff;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-panel.active {
            display: block;
        }

        .canvas-debug-bar .canvas-debug-bar-panel-section {
            margin-bottom: 24px;
        }

        .canvas-debug-bar .canvas-debug-bar-panel-section h3 {
            margin: 0 0 12px 0;
            color: #333333;
            font-size: 14px;
            font-weight: 600;
        }

        /* Info Grid */
        .canvas-debug-bar .canvas-debug-bar-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 8px;
        }

        .canvas-debug-bar .canvas-debug-bar-info-item {
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }

        .canvas-debug-bar .canvas-debug-bar-info-item .canvas-debug-bar-label {
            min-width: 120px;
            color: #666666;
        }

        .canvas-debug-bar .canvas-debug-bar-info-item .canvas-debug-bar-value {
            color: #333333;
            word-break: break-all;
        }

        /* Query List */
        .canvas-debug-bar .canvas-debug-bar-query-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .canvas-debug-bar .canvas-debug-bar-query-item {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 12px;
        }

        .canvas-debug-bar .canvas-debug-bar-query-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }

        .canvas-debug-bar .canvas-debug-bar-query-time {
            background: #28a745;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }

        .canvas-debug-bar .canvas-debug-bar-query-type {
            background: #007bff;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }

        .canvas-debug-bar .canvas-debug-bar-query-connection {
            color: #666666;
            font-size: 11px;
        }

        .canvas-debug-bar .canvas-debug-bar-query-sql code {
            background: #f8f9fa;
            color: #d63384;
            padding: 8px;
            border-radius: 3px;
            display: block;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            line-height: 1.4;
            white-space: pre-wrap;
            border: 1px solid #e0e0e0;
        }

        .canvas-debug-bar .canvas-debug-bar-query-params {
            margin-top: 8px;
            color: #666666;
            font-size: 12px;
        }

        /* Cache Items */
        .canvas-debug-bar .canvas-debug-bar-cache-stats {
            display: flex;
            gap: 24px;
            margin-bottom: 16px;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 4px;
            border: 1px solid #e0e0e0;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-stat {
            display: flex;
            gap: 8px;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-label {
            color: #666666;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-value {
            color: #0066cc;
            font-weight: 500;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            background: #f8f9fa;
            border-radius: 4px;
            border: 1px solid #e0e0e0;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-type {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            min-width: 40px;
            text-align: center;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-item.hit .canvas-debug-bar-cache-type {
            background: #28a745;
            color: white;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-item.miss .canvas-debug-bar-cache-type {
            background: #dc3545;
            color: white;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-key {
            flex: 1;
            color: #333333;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
        }

        .canvas-debug-bar .canvas-debug-bar-cache-time {
            color: #666666;
            font-size: 11px;
        }

        /* Signal Items */
        .canvas-debug-bar .canvas-debug-bar-signal-list,
        .canvas-debug-bar .canvas-debug-bar-aspect-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .canvas-debug-bar .canvas-debug-bar-signal-item,
        .canvas-debug-bar .canvas-debug-bar-aspect-item {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 12px;
        }

        .canvas-debug-bar .canvas-debug-bar-signal-header,
        .canvas-debug-bar .canvas-debug-bar-aspect-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 6px;
        }

        .canvas-debug-bar .canvas-debug-bar-signal-name,
        .canvas-debug-bar .canvas-debug-bar-aspect-name {
            color: #0066cc;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
        }

        .canvas-debug-bar .canvas-debug-bar-signal-time,
        .canvas-debug-bar .canvas-debug-bar-aspect-time {
            background: #fd7e14;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }

        .canvas-debug-bar .canvas-debug-bar-aspect-type {
            background: #6f42c1;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }

        .canvas-debug-bar .canvas-debug-bar-signal-details,
        .canvas-debug-bar .canvas-debug-bar-aspect-details {
            color: #666666;
            font-size: 12px;
        }

        /* Timeline */
        .canvas-debug-bar .canvas-debug-bar-timeline {
            display: flex;
            height: 40px;
            margin-bottom: 16px;
            border-radius: 4px;
            overflow: hidden;
            border: 1px solid #e0e0e0;
        }

        .canvas-debug-bar .canvas-debug-bar-timeline-item {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 4px;
            color: white;
            font-size: 11px;
            font-weight: bold;
            position: relative;
            min-width: 60px;
        }

        .canvas-debug-bar .canvas-debug-bar-timeline-label {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .canvas-debug-bar .canvas-debug-bar-timeline-time {
            font-size: 10px;
            opacity: 0.9;
        }

        .canvas-debug-bar .canvas-debug-bar-timeline-legend {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }

        .canvas-debug-bar .canvas-debug-bar-timeline-legend span {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            color: #666666;
        }

        .canvas-debug-bar .canvas-debug-bar-legend-color {
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }

        /* Scrollbar Styling */
        .canvas-debug-bar .canvas-debug-bar-debug-panel::-webkit-scrollbar,
        .canvas-debug-bar .canvas-debug-bar-debug-tabs::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-panel::-webkit-scrollbar-track,
        .canvas-debug-bar .canvas-debug-bar-debug-tabs::-webkit-scrollbar-track {
            background: #f8f9fa;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-panel::-webkit-scrollbar-thumb,
        .canvas-debug-bar .canvas-debug-bar-debug-tabs::-webkit-scrollbar-thumb {
            background: #ced4da;
            border-radius: 4px;
        }

        .canvas-debug-bar .canvas-debug-bar-debug-panel::-webkit-scrollbar-thumb:hover,
        .canvas-debug-bar .canvas-debug-bar-debug-tabs::-webkit-scrollbar-thumb:hover {
            background: #adb5bd;
        }
        
		.canvas-debug-bar-params-table {
		    width: 100%;
		    border-collapse: collapse;
		    margin-top: 8px;
		    font-size: 12px;
		    background: #f8f9fa;
		}
		
		.canvas-debug-bar-params-table th {
		    background: #e9ecef;
		    padding: 6px 10px;
		    text-align: left;
		    font-weight: 600;
		    border: 1px solid #dee2e6;
		    color: #495057;
		}
		
		.canvas-debug-bar-params-table td {
		    padding: 6px 10px;
		    border: 1px solid #dee2e6;
		    vertical-align: top;
		}
		
		.canvas-debug-bar-param-key {
		    font-weight: 500;
		    color: #007bff;
		    background: #f8f9fa;
		    width: 30%;
		}
		
		.canvas-debug-bar-param-value {
		    font-family: 'Courier New', monospace;
		    color: #212529;
		    word-break: break-word;
		}
		
		.canvas-debug-bar-query-params {
		    margin-top: 10px;
		}
		
		.canvas-debug-bar-query-params strong {
		    display: block;
		    margin-bottom: 5px;
		    color: #495057;
		}

        /* Responsive Design */
        @media (max-width: 768px) {
            .canvas-debug-bar .canvas-debug-bar-debug-stats {
                display: none;
            }
            
            .canvas-debug-bar .canvas-debug-bar-info-grid {
                grid-template-columns: 1fr;
            }
            
            .canvas-debug-bar .canvas-debug-bar-cache-stats {
                flex-direction: column;
                gap: 8px;
            }
            
            .canvas-debug-bar .canvas-debug-bar-timeline-legend {
                gap: 8px;
            }
            
			/* Add to your CSS */
			.canvas-debug-bar .canvas-debug-bar-headers-list,
			.canvas-debug-bar .canvas-debug-bar-params-list {
			    display: flex;
			    flex-direction: column;
			    gap: 4px;
			    max-height: 200px;
			    overflow-y: auto;
			}
			
			.canvas-debug-bar .canvas-debug-bar-header-item,
			.canvas-debug-bar .canvas-debug-bar-param-item {
			    display: flex;
			    padding: 4px 0;
			    border-bottom: 1px solid #f0f0f0;
			    font-size: 12px;
			}
			
			.canvas-debug-bar .canvas-debug-bar-header-name,
			.canvas-debug-bar .canvas-debug-bar-param-name {
			    min-width: 150px;
			    color: #666666;
			    font-weight: 500;
			}
			
			.canvas-debug-bar .canvas-debug-bar-header-value,
			.canvas-debug-bar .canvas-debug-bar-param-value {
			    color: #333333;
			    word-break: break-all;
			    font-family: 'Consolas', 'Monaco', monospace;
			}
			
.canvas-debug-bar .canvas-debug-bar-files-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.canvas-debug-bar .canvas-debug-bar-file-item {
    background: #f8f9fa;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 12px;
}

.canvas-debug-bar .canvas-debug-bar-file-item.invalid {
    border-color: #dc3545;
    background: #f8d7da;
}

.canvas-debug-bar .canvas-debug-bar-file-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
}

.canvas-debug-bar .canvas-debug-bar-file-name {
    color: #0066cc;
    font-family: 'Consolas', 'Monaco', monospace;
    font-weight: 500;
}

.canvas-debug-bar .canvas-debug-bar-file-size {
    color: #666666;
    font-size: 11px;
    background: #e9ecef;
    padding: 2px 6px;
    border-radius: 3px;
}

.canvas-debug-bar .canvas-debug-bar-file-error {
    color: white;
    background: #dc3545;
    font-size: 10px;
    font-weight: bold;
    padding: 2px 6px;
    border-radius: 3px;
}

.canvas-debug-bar .canvas-debug-bar-file-details {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.canvas-debug-bar .canvas-debug-bar-file-detail {
    display: flex;
    font-size: 12px;
}

.canvas-debug-bar .canvas-debug-bar-error {
    color: #dc3545;
    font-weight: 500;
}
        }
CSS;
		}
		
		private function getDataScript(Request $request): string {
			$jsonData = json_encode($this->dataProcessor->getDebugData($request), JSON_HEX_TAG | JSON_HEX_AMP);
			
			return <<<JS
        // Inject debug data and render
        document.addEventListener('DOMContentLoaded', function() {
            if (window.CanvasDebugBar) {
                window.CanvasDebugBar.render({$jsonData});
            }
        });
        JS;
		}
		
		/**
		 * Debugbar JS
		 * @return string
		 */
		private function getJs(): string {
			return <<<JS
window.CanvasDebugBar = {
    data: null,
    
    render: function(debugData) {
        this.data = debugData;
        this.renderStats();
        this.renderTabs();
        this.renderPanels();
    },
    
    renderStats: function() {
        const statsContainer = document.getElementById('debug-stats');
        const stats = this.data.stats;
        
        statsContainer.innerHTML = `
            <span class="canvas-debug-bar-stat">
                <span class="canvas-debug-bar-stat-label">Time:</span>
                <span class="canvas-debug-bar-stat-value">\${stats . time}ms</span>
            </span>
            <span class="canvas-debug-bar-stat">
                <span class="canvas-debug-bar-stat-label">Memory:</span>
                <span class="canvas-debug-bar-stat-value">\${stats . memory}</span>
            </span>
            <span class="canvas-debug-bar-stat">
                <span class="canvas-debug-bar-stat-label">Queries:</span>
                <span class="canvas-debug-bar-stat-value">\${this . data . queries . length}</span>
            </span>
            <span class="canvas-debug-bar-stat">
                <span class="canvas-debug-bar-stat-label">Cache:</span>
                <span class="canvas-debug-bar-stat-value">\${this . data . cache . hits} hits</span>
            </span>
        `;
    },
    
    renderTabs: function() {
        const tabsContainer = document.getElementById('debug-tabs');
        const tabs = [
            { id: 'request', label: `Request`, icon: `🗄️️` },
            { id: 'queries', label: `Database (\${this . data . queries . length})`, icon: '🗄️' },
        ];
        
        tabsContainer.innerHTML = tabs.map(tab => `
            <button class="canvas-debug-bar-debug-tab \${tab . id === 'request' ? 'active' : ''}"
                    onclick="CanvasDebugBar.showTab('\${tab . id}')">
                \${tab . icon} \${tab . label}
            </button>
        `).join('');
    },
    
    renderPanels: function() {
        const panelsContainer = document.getElementById('debug-panels');
        panelsContainer.innerHTML = `
            \${this . renderRequestPanel()}
            \${this . renderQueriesPanel()}
        `;
    },
    
	renderRequestPanel: function() {
	    const request = this.data.request;
	    const route = this.data.route;
	    
	    return `
	        <div id="panel-request" class="canvas-debug-bar-debug-panel active">
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
	                        <span class="canvas-debug-bar-value">\${this.formatRouteParams(route.parameters)}</span>
	                    </div>
	                    \${route.legacy ? `
	                    <div class="canvas-debug-bar-info-item">
	                        <span class="canvas-debug-bar-label">Legacy File:</span>
	                        <span class="canvas-debug-bar-value">\${route.legacyFile}</span>
	                    </div>
	                    ` : ''}
	                </div>
	            </div>
	            
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
	                        <span class="canvas-debug-bar-value" title="\${request.userAgent}">\${this.truncate(request.userAgent, 60)}</span>
	                    </div>
	                    <div class="canvas-debug-bar-info-item">
	                        <span class="canvas-debug-bar-label">Referer:</span>
	                        <span class="canvas-debug-bar-value">\${request.referer || 'None'}</span>
	                    </div>
	                </div>
	            </div>
	
				\${Object.keys(request.request).length > 0 ? `
	            <div class="canvas-debug-bar-panel-section">
	                <h3>POST Data</h3>
	                <div class="canvas-debug-bar-params-list">
	                    \${Object.entries(request.request).map(([name, value]) => `
	                        <div class="canvas-debug-bar-param-item">
	                            <span class="canvas-debug-bar-param-name">\${name}:</span>
	                            <span class="canvas-debug-bar-param-value">\${this.escapeHtml(JSON.stringify(value))}</span>
	                        </div>
	                    `).join('')}
	                </div>
	            </div>
	            ` : ''}
	
				\${Object.keys(request.files).length > 0 ? `
				<div class="canvas-debug-bar-panel-section">
				    <h3>Uploaded Files</h3>
				    <div class="canvas-debug-bar-files-list">
				        \${Object.entries(request.files).map(([name, file]) => `
				            <div class="canvas-debug-bar-file-item \${file.isValid ? 'valid' : 'invalid'}">
				                <div class="canvas-debug-bar-file-header">
				                    <span class="canvas-debug-bar-file-name">\${name}</span>
				                    <span class="canvas-debug-bar-file-size">\${file.sizeFormatted}</span>
				                    \${!file.isValid ? `<span class="canvas-debug-bar-file-error">ERROR</span>` : ''}
				                </div>
				                <div class="canvas-debug-bar-file-details">
				                    <div class="canvas-debug-bar-file-detail">
				                        <span class="canvas-debug-bar-label">Original Name:</span>
				                        <span class="canvas-debug-bar-value">\${this.escapeHtml(file.originalName || 'N/A')}</span>
				                    </div>
				                    <div class="canvas-debug-bar-file-detail">
				                        <span class="canvas-debug-bar-label">MIME Type:</span>
				                        <span class="canvas-debug-bar-value">\${file.mimeType || 'Unknown'}</span>
				                    </div>
				                    <div class="canvas-debug-bar-file-detail">
				                        <span class="canvas-debug-bar-label">Extension:</span>
				                        <span class="canvas-debug-bar-value">\${file.extension || 'None'}</span>
				                    </div>
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
				
	            \${Object.keys(request.cookies).length > 0 ? `
	            <div class="canvas-debug-bar-panel-section">
	                <h3>Cookies</h3>
	                <div class="canvas-debug-bar-params-list">
	                    \${Object.entries(request.cookies).map(([name, value]) => `
	                        <div class="canvas-debug-bar-param-item">
	                            <span class="canvas-debug-bar-param-name">\${name}:</span>
	                            <span class="canvas-debug-bar-param-value">\${this.escapeHtml(value)}</span>
	                        </div>
	                    `).join('')}
	                </div>
	            </div>
	            ` : ''}
	        </div>
	    `;
	},
	
	renderQueriesPanel: function() {
	    const formatParameters = (params) => {
	        if (!params || Object.keys(params).length === 0) {
	            return '<em>No parameters</em>';
	        }
	        
	        const rows = Object.entries(params).map(([key, value]) => `
	            <tr>
	                <td class="canvas-debug-bar-param-key">\${this.escapeHtml(key)}</td>
	                <td class="canvas-debug-bar-param-value">\${this.escapeHtml(JSON.stringify(value))}</td>
	            </tr>
	        `).join('');
	        
	        return `
	            <table class="canvas-debug-bar-params-table">
	                <thead>
	                    <tr>
	                        <th>Parameter</th>
	                        <th>Value</th>
	                    </tr>
	                </thead>
	                <tbody>
	                    \${rows}
	                </tbody>
	            </table>
	        `;
	    };
	
	    const queries = this.data.queries.map(query => `
	        <div class="canvas-debug-bar-query-item">
	            <div class="canvas-debug-bar-query-header">
	                <span class="canvas-debug-bar-query-time">\${query.execution_time_ms}ms</span>
	            </div>
	            <div class="canvas-debug-bar-query-sql">
	                <code>\${this.escapeHtml(query.query)}</code>
	            </div>
	            <div class="canvas-debug-bar-query-params">
	                <strong>Parameters:</strong>
	                \${formatParameters(query.bound_parameters)}
	            </div>
	        </div>
	    `).join('');
	    
	    return `
	        <div id="panel-queries" class="canvas-debug-bar-debug-panel">
	            <div class="canvas-debug-bar-panel-section">
	                <h3>Database Queries (\${this.data.queries.length} queries, \${this.data.stats.queryTime}ms total)</h3>
	                <div class="canvas-debug-bar-query-list">
	                    \${queries}
	                </div>
	            </div>
	        </div>
	    `;
	},
    
    toggle: function() {
        const debugBar = document.getElementById('canvas-debug-bar');
        debugBar.classList.toggle('minimized');
    },
    
    showTab: function(tabName) {
        // Hide all panels
        document.querySelectorAll('.canvas-debug-bar-debug-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        
        // Hide all tabs
        document.querySelectorAll('.canvas-debug-bar-debug-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Show selected panel and tab
        const panel = document.getElementById(`panel-\${tabName}`);
        
        if (panel) {
            panel.classList.add('active');
        }
        
        event.target.classList.add('active');
    },
    
    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
	// Helper methods to add to the CanvasDebugBar object:
	formatRouteParams: function(params) {
	    if (!params || Object.keys(params).length === 0) {
	        return 'None';
	    }
     
	    return Object.entries(params).map(([key, value]) => `\${key}: \${value}`).join(', ');
	},
	
	truncate: function(str, length) {
	    if (!str) return '';
	    return str.length > length ? str.substring(0, length) + '...' : str;
	}
};
JS;
		
		}
		
		/**
		 * Returns the position of the </body> tag
		 * @param string $content
		 * @return false|int
		 */
		private function getEndOfBodyPosition(string $content): false|int {
			return strpos($content, "</body>");
		}
	}