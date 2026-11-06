<?php
	
	namespace Quellabs\Canvas\Inspector\Helpers;
	
	use Quellabs\Canvas\Inspector\Panels\QueryPanel;
	use Quellabs\Canvas\Inspector\Panels\RequestPanel;
	use Quellabs\Canvas\Inspector\Panels\WakaPACPanel;
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
		 * Default panels shipped with the Canvas inspector
		 */
		private const array DEFAULT_PANELS = [
			RequestPanel::class
		];

		/**
		 * Base64-encoded PNG of the Canvas gnome mascot, cropped to the head and
		 * shown next to the header logo text. Inlined so the debug bar never
		 * depends on a request to the public website to render.
		 */
		private const string LOGO_ICON_BASE64 = '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';


		/**
		 * @var EventCollectorInterface Event collector
		 */
		private EventCollectorInterface $eventCollector;
		
		/**
		 * @var InspectorPanelInterface[] Array of registered panels indexed by name
		 */
		private array $panels = [];
		
		/**
		 * Initialize the debug registry with an event collector
		 * @param EventCollectorInterface $eventCollector Service for collecting debug events
		 * @param ConfigurationInterface $config Inspector configuration
		 */
		public function __construct(EventCollectorInterface $eventCollector, ConfigurationInterface $config) {
			$this->eventCollector = $eventCollector;
			
			// Merge default panels with user-defined panels, ensuring defaults appear first
			// in tab order and duplicates are removed
			$configPanels = $config->get('panels', []);
			$configPanels = is_array($configPanels) ? $configPanels : [];
			
			// Validate panels
			$validatedPanels = [];
			
			foreach (array_merge(self::DEFAULT_PANELS, $configPanels) as $panel) {
				if (!is_string($panel) || !class_exists($panel)) {
					throw new \InvalidArgumentException("Invalid panel class");
				}
				
				if (!is_subclass_of($panel, InspectorPanelInterface::class)) {
					throw new \InvalidArgumentException("Must implement InspectorPanelInterface");
				}
				
				$validatedPanels[] = $panel;
			}
			
			// Instantiate the requested panels
			$this->initializePanels(array_unique($validatedPanels));
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
		 * @return array<string, mixed> Merged statistics from all panels
		 */
		public function getStats(): array {
			$stats = [];
			
			foreach ($this->panels as $panel) {
				$stats = array_merge($stats, $panel->getStats());
			}
			
			return $stats;
		}
		
		/**
		 * Render the complete debug bar with all panels
		 * @param Request $request The current HTTP request
		 * @return string Complete HTML for the debug bar
		 * @throws \JsonException
		 */
		public function render(Request $request): string {
			$css = [];
			$panelData = [];
			$jsTemplates = [];
			
			foreach ($this->panels as $panel) {
				// Let the panel pull its relevant events from the collector
				$panel->processEvents($this->eventCollector);
				
				// Build a unique JS function name for client-side rendering (e.g. "renderQueryPanel")
				$functionName = 'render' . ucfirst($panel->getName()) . 'Panel';
				
				// Store the JS template with its function name for later registration on window
				$jsTemplates[$panel->getName()] = [
					'function' => $functionName,
					'code'     => $panel->getJsTemplate()
				];
				
				// Collect panel-specific CSS
				$css[] = $panel->getCss();
				
				// Merge the panel's data with its display metadata (icon, tab label)
				$panelData[$panel->getName()] = array_merge($panel->getData($request), [
					'icon'  => $panel->getIcon(),
					'label' => $panel->getTabLabel()
				]);
			}
			
			// Combine everything into the final debug bar HTML
			return $this->renderDebugBar($jsTemplates, $css, $panelData, $this->getStats());
		}
		
		/**
		 * Initialize panels from a list of class names
		 * @param array<int, class-string<InspectorPanelInterface>> $panels Array of fully qualified panel class names
		 * @return void
		 */
		private function initializePanels(array $panels): void {
			foreach ($panels as $className) {
				try {
					// Validate that the class exists
					if (!class_exists($className)) {
						throw new \InvalidArgumentException("Panel class '{$className}' not found");
					}
					
					// Create the panel
					$panel = new $className();
					
					// Register the panel
					$this->addPanel($panel);
					
				} catch (\Exception $e) {
					// Log the error but don't break the entire debugbar
					error_log("Failed to initialize panel '{$className}': " . $e->getMessage());
				}
			}
		}
		
		/**
		 * Generate the complete HTML output for the debug bar
		 * @param array<string, array{function: string, code: string}> $jsTemplates JavaScript template functions for each panel
		 * @param array<int, string> $css CSS styles from all panels
		 * @param array<string, array<string, mixed>> $panelData Data for all panels including metadata
		 * @param array<string, mixed> $stats Statistics to display in the header
		 * @return string Complete HTML markup for the debug bar
		 * @throws \JsonException
		 */
		private function renderDebugBar(array $jsTemplates, array $css, array $panelData, array $stats): string {
			// Inlined so the header icon never depends on a request to the public website
			$logoIcon = self::LOGO_ICON_BASE64;

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
			], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
			
			return <<<HTML
<!-- Canvas Inspector -->
<div id="canvas-debug-bar" class="canvas-debug-bar minimized">
    <!-- Header with logo, arrow, statistics, and controls -->
    <div class="canvas-debug-bar-header" onclick="CanvasDebugBar.toggle()">
        <span class="canvas-debug-bar-arrow" id="debug-bar-arrow">▲</span>
        <div class="canvas-debug-bar-logo">
            Canvas Inspector
            <img src="data:image/png;base64,{$logoIcon}" alt="" class="canvas-debug-bar-logo-icon">
        </div>
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

/* Gnome mascot icon next to the logo text */
.canvas-debug-bar-logo-icon {
    width: 20px;
    height: 20px;
    object-fit: contain;
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
    margin: 0;
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