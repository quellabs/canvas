<?php
	
	namespace Quellabs\Canvas\Inspector\Helpers;
	
	use Quellabs\Canvas\Configuration\Configuration;
	use Quellabs\Canvas\Inspector\EventCollector;
	use Quellabs\Canvas\Inspector\Panels\QueryPanel;
	use Quellabs\Canvas\Inspector\Panels\RequestPanel;
	use Quellabs\Contracts\Configuration\ConfigurationInterface;
	use Quellabs\Contracts\Inspector\EventCollectorInterface;
	use Quellabs\Contracts\Inspector\InspectorPanelInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Central registry for managing debug panels and rendering the inspector
	 *
	 * This class acts as the main coordinator for the Canvas debug bar system,
	 * managing multiple debug panels and orchestrating their rendering into
	 * a unified debug interface.
	 */
	class Registry {
		
		/**
		 * @var EventCollector Collects all debug events during request processing
		 */
		private EventCollector $eventCollector;
		
		/**
		 * @var InspectorPanelInterface[] Array of registered panels indexed by name
		 */
		private array $panels = [];
		
		/**
		 * Initialize the debug registry with an event collector
		 * @param EventCollector $eventCollector Service for collecting debug events
		 * @param ConfigurationInterface $config
		 */
		public function __construct(EventCollectorInterface $eventCollector, ConfigurationInterface $config) {
			$this->eventCollector = $eventCollector;
			
			if (empty($config->get('panels', []))) {
				$this->initializeDefaultPanels();
			} else {
				$this->initializePanels($config->get('panels', []));
			}
		}
		
		/**
		 * Register a new debug panel
		 * @param InspectorPanelInterface $panel The panel to add to the registry
		 */
		public function addPanel(InspectorPanelInterface $panel): void {
			$this->panels[$panel->getName()] = $panel;
		}
		
		/**
		 * Collect statistics from all registered panels
		 * @return array Merged statistics from all panels
		 */
		public function getStats(): array {
			$stats = [];
			foreach ($this->panels as $panel) {
				$stats = array_merge($stats, $panel->getStats());
			}
			
			return $stats;
		}
		
		/**
		 * Get all registered panels
		 * @return array Array of registered debug panels
		 */
		public function getPanels(): array {
			return $this->panels;
		}
		
		/**
		 * Render the complete debug bar with all panels
		 *
		 * This method orchestrates the entire rendering process:
		 * 1. Processes events in all panels
		 * 2. Collects data, templates, and CSS from panels
		 * 3. Renders the final HTML output
		 *
		 * @param Request $request The current HTTP request
		 * @return string Complete HTML for the debug bar
		 */
		public function render(Request $request): string {
			// Process events in all panels first to ensure data is up-to-date
			foreach ($this->panels as $panel) {
				$panel->processEvents();
			}
			
			$css = []; // Collect JavaScript templates for dynamic panel rendering
			$panelData = []; // Collect CSS from all panels
			$jsTemplates = []; // Collect data from all panels with additional metadata
			
			foreach ($this->panels as $panel) {
				// Generate JavaScript function name from panel name (e.g., 'database' -> 'renderDatabasePanel')
				$functionName = 'render' . ucfirst($panel->getName()) . 'Panel';
				
				// Collect panel-specific JS
				$jsTemplates[$panel->getName()] = [
					'function' => $functionName,
					'code'     => $panel->getJsTemplate()
				];
				
				// Collect panel-specific CSS
				$css[] = $panel->getCss();
				
				// Collect panel data with additional metadata for tab rendering
				$panelData[$panel->getName()] = array_merge($panel->getData($request), [
					'icon'  => $panel->getIcon(),
					'label' => $panel->getTabLabel()
				]);
			}
			
			return $this->renderDebugBar($jsTemplates, $css, $panelData, $this->getStats());
		}
		
		/**
		 * Initialize panels based on configuration
		 * @param array $panels $config Array where key = panel name, value = class name
		 * @return void
		 */
		private function initializePanels(array $panels): void {
			foreach ($panels as $panelName => $className) {
				try {
					// Validate that the class exists
					if (!class_exists($className)) {
						throw new \InvalidArgumentException("Panel class '{$className}' not found");
					}
					
					// Validate that the class implements the required interface
					if (!in_array(InspectorPanelInterface::class, class_implements($className))) {
						throw new \InvalidArgumentException("Panel class '{$className}' must implement DebugPanelInterface");
					}
					
					// Create the panel
					$panel = new $className($this->eventCollector);
					
					// Register the panel
					$this->addPanel($panel);
					
				} catch (\Exception $e) {
					// Log the error but don't break the entire debugbar
					error_log("Failed to initialize panel '{$panelName}': " . $e->getMessage());
				}
			}
		}
		
		/**
		 * Register the default debug panels that come with the debugbar.
		 * These provide basic debugging information like request details and database queries.
		 */
		private function initializeDefaultPanels(): void {
			// Panel for displaying request information (headers, parameters, etc.)
			$this->addPanel(new RequestPanel($this->eventCollector));
			
			// Panel for displaying database queries and performance metrics
			$this->addPanel(new QueryPanel($this->eventCollector));
		}
		
		/**
		 * Generate the complete HTML output for the debug bar
		 * @param array $jsTemplates JavaScript template functions for each panel
		 * @param array $css CSS styles from all panels
		 * @param array $panelData Data for all panels including metadata
		 * @param array $stats Statistics to display in the header
		 * @return string Complete HTML markup for the debug bar
		 */
		private function renderDebugBar(array $jsTemplates, array $css, array $panelData, array $stats): string {
			// Combine all panel-specific CSS
			$cssContent = implode("\n", array_filter($css));
			
			// Generate JavaScript functions from panel templates
			$jsFunctions = [];
			foreach ($jsTemplates as $template) {
				$jsFunctions[] = "window.{$template['function']} = function(data) {\n{$template['code']}\n};";
			}
			
			$jsFunctionsCode = implode("\n\n", $jsFunctions);
			
			// Create template function name mapping for the client-side renderer
			$templateMapping = array_map(function ($template) {
				return $template['function'];
			}, $jsTemplates);
			
			// Prepare data for JavaScript initialization
			$jsData = json_encode([
				'stats'     => $stats,
				'panels'    => $panelData,
				'templates' => $templateMapping
			], JSON_HEX_TAG | JSON_HEX_AMP);
			
			return <<<HTML
<!-- Canvas Inspector -->
<div id="canvas-debug-bar" class="canvas-debug-bar minimized">
    <!-- Header with logo, arrow, statistics, and controls -->
    <div class="canvas-debug-bar-header" onclick="CanvasDebugBar.toggle()">
        <span class="canvas-debug-bar-arrow" id="debug-bar-arrow">▲</span>
        <div class="canvas-debug-bar-logo">Canvas Inspector</div>
        <div class="canvas-debug-bar-stats" id="debug-stats"></div>
        <div class="canvas-debug-bar-controls">
            <label class="canvas-debug-remain-open" onclick="event.stopPropagation()">
                <input type="checkbox" id="canvas-debug-remain-open" onchange="CanvasDebugBar.toggleRemainOpen()">
                <span>Remain Open</span>
            </label>
        </div>
    </div>
    
    <!-- Main content area with tabs and panels -->
    <div class="canvas-debug-bar-content">
        <div class="canvas-debug-bar-tabs" id="debug-tabs"></div>
        <div class="canvas-debug-bar-panels" id="debug-panels"></div>
    </div>
</div>

<style>
	{$this->getBaseCss()}
	{$this->getCommonComponentsCss()}
	{$cssContent}
</style>

<script>
	{$this->getBaseJs()}
	{$this->getCommonHelpers()}
	{$jsFunctionsCode}

	// Initialize debug bar when DOM is ready
	document.addEventListener('DOMContentLoaded', function() {
	    if (window.CanvasDebugBar) {
	        window.CanvasDebugBar.init({$jsData});
	    }
	});
</script>
HTML;
		}
		
		/**
		 * Get the base CSS styles for the debug bar
		 * @return string CSS styles for the debug bar structure and layout
		 */
		private function getBaseCss(): string {
			return <<<CSS
/* Canvas Debug Bar Base Styles */
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
    max-height: 80vh;
    overflow: hidden;
}

/* Minimized state - only show header */
.canvas-debug-bar.minimized {
    max-height: 40px;
}

.canvas-debug-bar.minimized .canvas-debug-bar-content {
    display: none;
}

/* Header containing logo and stats */
.canvas-debug-bar-header {
    display: flex;
    align-items: center;
    padding: 10px 16px;
    background: #f8f9fa;
    border-bottom: 1px solid #e0e0e0;
    cursor: pointer;
    user-select: none;
}

.canvas-debug-bar-header:hover {
    background: #f0f0f0;
}

/* Arrow indicator */
.canvas-debug-bar-arrow {
    font-size: 12px;
    margin-right: 8px;
    display: inline-block;
    color: #0066cc;
    font-weight: bold;
}

/* Logo/branding */
.canvas-debug-bar-logo {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 600;
    color: #0066cc;
}

/* Statistics display in header */
.canvas-debug-bar-stats {
    display: flex;
    gap: 20px;
    margin-left: auto;
    margin-right: 20px;
}

.canvas-debug-bar-stat {
    display: flex;
    gap: 4px;
}

.canvas-debug-bar-stat-label {
    color: #666666;
}

.canvas-debug-bar-stat-value {
    color: #0066cc;
    font-weight: 500;
}

/* Controls section */
.canvas-debug-bar-controls {
    display: flex;
    align-items: center;
    margin-left: 20px;
}

/* Remain open checkbox styling */
.canvas-debug-remain-open {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: #666666;
    cursor: pointer;
    user-select: none;
    padding: 4px 8px;
    border-radius: 3px;
    transition: all 0.2s ease;
}

.canvas-debug-remain-open:hover {
    background: #e9ecef;
}

.canvas-debug-remain-open input[type="checkbox"] {
    margin: 0;
    cursor: pointer;
}

.canvas-debug-remain-open input[type="checkbox"]:checked + span {
    color: #0066cc;
    font-weight: 500;
}

/* Main content area */
.canvas-debug-bar-content {
    display: flex;
    flex-direction: column;
    height: 400px;
}

/* Tab navigation */
.canvas-debug-bar-tabs {
    display: flex;
    background: #f8f9fa;
    border-bottom: 1px solid #e0e0e0;
    overflow-x: auto;
}

.canvas-debug-bar-tab {
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

.canvas-debug-bar-tab:hover {
    background: #e9ecef;
    color: #333333;
}

.canvas-debug-bar-tab.active {
    background: #ffffff;
    color: #0066cc;
    border-bottom: 2px solid #0066cc;
}

/* Panel container */
.canvas-debug-bar-panels {
    flex: 1;
    overflow: hidden;
}

/* Individual panel styling */
.canvas-debug-bar-panel {
    display: none;
    height: 100%;
    overflow-y: auto;
    padding: 16px;
    background: #ffffff;
}

.canvas-debug-bar-panel.active {
    display: block;
}

/* Panel content sections */
.debug-panel-section {
    margin-bottom: 24px;
}

.debug-panel-section h3 {
    margin: 0 0 12px 0;
    color: #333333;
    font-size: 14px;
    font-weight: 600;
}
CSS;
		}
		
		/**
		 * Get common component CSS that can be reused across panels
		 * @return string CSS for reusable components like tables, grids, badges
		 */
		private function getCommonComponentsCss(): string {
			return <<<CSS
/* Common Components - Reusable across all panels */

/* Parameter/Data Tables - Used for query params, route params, cookies, etc. */
.canvas-debug-params-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 8px;
    font-size: 12px;
    background: #ffffff;
    border: 1px solid #dee2e6;
}

.canvas-debug-params-table th {
    background: #e9ecef;
    padding: 6px 10px;
    text-align: left;
    font-weight: 600;
    border: 1px solid #dee2e6;
    color: #495057;
}

.canvas-debug-params-table td {
    padding: 6px 10px;
    border: 1px solid #dee2e6;
    vertical-align: top;
}

.canvas-debug-param-key {
    font-weight: 500;
    color: #495057;
    background: #f8f9fa;
}

.canvas-debug-param-value {
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    font-size: 11px;
    word-break: break-all;
}

/* Info Grid - Used for displaying key-value pairs in a responsive grid */
.canvas-debug-info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 8px;
}

.canvas-debug-info-item {
    display: flex;
    padding: 8px 0;
    border-bottom: 1px solid #e0e0e0;
}

.canvas-debug-info-item .canvas-debug-label {
    min-width: 120px;
    color: #666666;
    font-weight: 500;
}

.canvas-debug-info-item .canvas-debug-value {
    color: #333333;
    word-break: break-all;
}

/* Time/Performance Badges */
.canvas-debug-time-badge {
    background: #28a745;
    color: white;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
    min-width: 45px;
    text-align: center;
}

.canvas-debug-time-badge.slow {
    background: #ffc107;
    color: #212529;
}

.canvas-debug-time-badge.very-slow {
    background: #dc3545;
}

/* Status Badges */
.canvas-debug-status-badge {
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: bold;
    text-transform: uppercase;
}

.canvas-debug-status-badge.success {
    background: #d4edda;
    color: #155724;
}

.canvas-debug-status-badge.error {
    background: #f8d7da;
    color: #721c24;
}

.canvas-debug-status-badge.warning {
    background: #fff3cd;
    color: #856404;
}

/* Code Blocks - For SQL, templates, etc. */
.canvas-debug-code {
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

/* Item Lists - For queries, files, etc. */
.canvas-debug-item-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.canvas-debug-item {
    background: #f8f9fa;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 12px;
}

.canvas-debug-item.error {
    border-color: #dc3545;
    background: #f8d7da;
}

.canvas-debug-item-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
}

.canvas-debug-item-content {
    margin-top: 8px;
}

/* Expandable Sections */
.canvas-debug-expandable {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    margin-bottom: 8px;
}

.canvas-debug-expandable-header {
    background: #f8f9fa;
    padding: 8px 12px;
    cursor: pointer;
    user-select: none;
    display: flex;
    align-items: center;
    gap: 8px;
}

.canvas-debug-expandable-header:hover {
    background: #e9ecef;
}

.canvas-debug-expandable-content {
    padding: 12px;
    border-top: 1px solid #e0e0e0;
    display: none;
}

.canvas-debug-expandable.expanded .canvas-debug-expandable-content {
    display: block;
}

/* Utility Classes */
.canvas-debug-text-muted {
    color: #6c757d;
    font-style: italic;
}

.canvas-debug-text-small {
    font-size: 11px;
}

.canvas-debug-text-mono {
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
}

.canvas-debug-text-break {
    word-break: break-all;
}

.canvas-debug-mb-0 { margin-bottom: 0; }
.canvas-debug-mb-1 { margin-bottom: 4px; }
.canvas-debug-mb-2 { margin-bottom: 8px; }
.canvas-debug-mb-3 { margin-bottom: 12px; }
CSS;
		}
		
		/**
		 * Get common JavaScript helper functions
		 * @return string JavaScript helper functions for use in panel templates
		 */
		private function getCommonHelpers(): string {
			return <<<JS
/**
 * Common helper functions for debug panels
 */
window.CanvasDebugHelpers = {
    /**
     * Format parameters into a standardized table
     */
    formatParamsTable: function(params, emptyMessage = 'No parameters') {
        if (!params || Object.keys(params).length === 0) {
            return `<em class="canvas-debug-text-muted">\${emptyMessage}</em>`;
        }
        
        const rows = Object.entries(params).map(([key, value]) => `
            <tr>
                <td class="canvas-debug-param-key">\${escapeHtml(key)}</td>
                <td class="canvas-debug-param-value">\${escapeHtml(JSON.stringify(value))}</td>
            </tr>
        `).join('');
        
        return `
            <table class="canvas-debug-params-table">
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
    },

    /**
     * Format time with appropriate badge styling
     */
    formatTimeBadge: function(timeMs) {
        let cssClass = 'canvas-debug-time-badge';
        if (timeMs > 1000) {
            cssClass += ' very-slow';
        } else if (timeMs > 100) {
            cssClass += ' slow';
        }
        
        return `<span class="\${cssClass}">\${timeMs}ms</span>`;
    },

    /**
     * Truncate long strings with ellipsis
     */
    truncate: function(str, length = 60) {
        if (!str) return '';
        return str.length > length ? str.substring(0, length) + '...' : str;
    },

    /**
     * Format route parameters for display
     */
    formatRouteParams: function(params) {
        if (!params || Object.keys(params).length === 0) {
            return '<em class="canvas-debug-text-muted">None</em>';
        }
        return Object.entries(params)
            .map(([key, value]) => `\${key}: \${value}`)
            .join(', ');
    },

    /**
     * Create an expandable section
     */
    createExpandable: function(title, content, expanded = false) {
        const expandedClass = expanded ? 'expanded' : '';
        return `
            <div class="canvas-debug-expandable \${expandedClass}">
                <div class="canvas-debug-expandable-header" onclick="this.parentElement.classList.toggle('expanded')">
                    <span>▶</span>
                    <span>\${title}</span>
                </div>
                <div class="canvas-debug-expandable-content">
                    \${content}
                </div>
            </div>
        `;
    }
};

// Make helpers globally available
window.formatParamsTable = window.CanvasDebugHelpers.formatParamsTable;
window.formatTimeBadge = window.CanvasDebugHelpers.formatTimeBadge;
window.truncateText = window.CanvasDebugHelpers.truncate;
window.formatRouteParams = window.CanvasDebugHelpers.formatRouteParams;
window.createExpandable = window.CanvasDebugHelpers.createExpandable;
JS;
		}
		
		/**
		 * Get the base JavaScript functionality for the debug bar
		 * @return string JavaScript code for debug bar interaction and rendering
		 */
		private function getBaseJs(): string {
			return <<<JS
/**
 * Canvas Debug Bar Client-Side Controller
 *
 * Handles all client-side functionality including:
 * - Initialization and data management
 * - Tab switching and panel display
 * - Statistics rendering
 * - Panel content rendering via templates
 * - Persistent state management
 */
window.CanvasDebugBar = {
    data: null,
    
    /**
     * Initialize the debug bar with data from the server
     * @param {Object} debugData Data containing stats, panels, and templates
     */
    init: function(debugData) {
        this.data = debugData;
        this.renderStats();
        this.renderTabs();
        this.renderPanels();
        this.restoreState();
    },
    
    /**
     * Render statistics in the header bar
     */
    renderStats: function() {
        const statsContainer = document.getElementById('debug-stats');
        const stats = this.data.stats;
        
        statsContainer.innerHTML = Object.entries(stats).map(([key, value]) => `
            <span class="canvas-debug-bar-stat">
                <span class="canvas-debug-bar-stat-label">\${this.formatStatLabel(key)}:</span>
                <span class="canvas-debug-bar-stat-value">\${value}</span>
            </span>
        `).join('');
    },
    
    /**
     * Render tab navigation buttons
     */
    renderTabs: function() {
        const tabsContainer = document.getElementById('debug-tabs');
        const panels = this.data.panels;
        
        tabsContainer.innerHTML = Object.entries(panels).map(([name, panelData], index) => `
            <button class="canvas-debug-bar-tab \${index === 0 ? 'active' : ''}"
                    onclick="CanvasDebugBar.showTab('\${name}')">
                \${panelData.icon || '📊'} \${panelData.label || name}
            </button>
        `).join('');
    },
    
    /**
     * Render all panel contents using their respective templates
     */
    renderPanels: function() {
        const panelsContainer = document.getElementById('debug-panels');
        const panels = this.data.panels;
        const templates = this.data.templates;
        
        panelsContainer.innerHTML = Object.entries(panels).map(([name, panelData], index) => {
            const template = templates[name];
            let content = '';
            
            // Use panel-specific template if available, otherwise fallback to JSON
            if (template && typeof window[template] === 'function') {
                content = window[template](panelData);
            } else {
                content = `<pre>\${JSON.stringify(panelData, null, 2)}</pre>`;
            }
            
            return `
                <div id="panel-\${name}" class="canvas-debug-bar-panel \${index === 0 ? 'active' : ''}">
                    \${content}
                </div>
            `;
        }).join('');
    },
    
    /**
     * Toggle debug bar between minimized and expanded states
     */
    toggle: function() {
        const debugBar = document.getElementById('canvas-debug-bar');
        const isMinimized = debugBar.classList.contains('minimized');
        
        if (isMinimized) {
            debugBar.classList.remove('minimized');
            this.saveState({ expanded: true });
        } else {
            debugBar.classList.add('minimized');
            this.saveState({ expanded: false });
        }
        
        this.updateArrow();
    },
    
    /**
     * Toggle the "remain open" functionality
     */
    toggleRemainOpen: function() {
        const checkbox = document.getElementById('canvas-debug-remain-open');
        this.saveState({ remainOpen: checkbox.checked });
    },
    
    /**
     * Update the arrow direction based on current state
     */
    updateArrow: function() {
        const arrow = document.getElementById('debug-bar-arrow');
        const debugBar = document.getElementById('canvas-debug-bar');
        
        if (debugBar.classList.contains('minimized')) {
            arrow.textContent = '▲';  // Point up when minimized (indicating it can expand up)
        } else {
            arrow.textContent = '▼';  // Point down when expanded (indicating it can minimize down)
        }
    },
    
    /**
     * Save debug bar state to localStorage
     * @param {Object} state State object to save
     */
    saveState: function(state) {
        try {
            const currentState = this.getState();
            const newState = Object.assign(currentState, state);
            localStorage.setItem('canvas-debug-bar-state', JSON.stringify(newState));
        } catch (e) {
            // Fail silently if localStorage is not available
            console.warn('Canvas Debug Bar: Unable to save state to localStorage');
        }
    },
    
    /**
     * Get current debug bar state from localStorage
     * @return {Object} Current state object
     */
    getState: function() {
        try {
            const state = localStorage.getItem('canvas-debug-bar-state');
            return state ? JSON.parse(state) : { expanded: false, remainOpen: false };
        } catch (e) {
            return { expanded: false, remainOpen: false };
        }
    },
    
    /**
     * Restore debug bar state from localStorage
     */
    restoreState: function() {
        const state = this.getState();
        const debugBar = document.getElementById('canvas-debug-bar');
        const checkbox = document.getElementById('canvas-debug-remain-open');
        
        // Restore remain open checkbox
        checkbox.checked = state.remainOpen || false;
        
        // Restore expanded state only if "remain open" is checked
        if (state.remainOpen && state.expanded) {
            debugBar.classList.remove('minimized');
        }
        
        this.updateArrow();
    },
    
    /**
     * Switch to a specific tab/panel
     * @param {string} tabName Name of the tab to show
     */
    showTab: function(tabName) {
        // Hide all panels and tabs
        document.querySelectorAll('.canvas-debug-bar-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        
        document.querySelectorAll('.canvas-debug-bar-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Show selected panel
        const panel = document.getElementById(`panel-\${tabName}`);

        if (panel) {
            panel.classList.add('active');
        }
        
        // Activate clicked tab
        event.target.classList.add('active');
    },
    
    /**
     * Format statistic labels for display (convert snake_case to Title Case)
     * @param {string} key The statistic key to format
     * @return {string} Formatted label
     */
    formatStatLabel: function(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    },
    
    /**
     * Escape HTML characters to prevent XSS
     * @param {string} text Text to escape
     * @return {string} HTML-escaped text
     */
    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// Make escapeHtml globally available for panel templates
window.escapeHtml = window.CanvasDebugBar.escapeHtml;
JS;
		}
	}