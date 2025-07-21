<?php
	
	namespace Quellabs\Canvas\Debugbar;
	
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * Central registry for managing debug panels and rendering the debug bar
	 *
	 * This class acts as the main coordinator for the Canvas debug bar system,
	 * managing multiple debug panels and orchestrating their rendering into
	 * a unified debug interface.
	 */
	class DebugRegistry {

		/**
		 * @var DebugEventCollector Collects all debug events during request processing
		 */
		private DebugEventCollector $eventCollector;
		
		/**
		 * @var DebugPanelInterface[] Array of registered panels indexed by name
		 */
		private array $panels = [];
		
		/**
		 * Initialize the debug registry with an event collector
		 *
		 * @param DebugEventCollector $eventCollector Service for collecting debug events
		 */
		public function __construct(DebugEventCollector $eventCollector) {
			$this->eventCollector = $eventCollector;
		}
		
		/**
		 * Register a new debug panel
		 *
		 * @param DebugPanelInterface $panel The panel to add to the registry
		 */
		public function addPanel(DebugPanelInterface $panel): void {
			$this->panels[$panel->getName()] = $panel;
		}
		
		/**
		 * Collect statistics from all registered panels
		 *
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
			
			// Collect JavaScript templates for dynamic panel rendering
			$jsTemplates = [];
			// Collect CSS from all panels
			$css = [];
			// Collect data from all panels with additional metadata
			$panelData = [];
			
			foreach ($this->panels as $panel) {
				// Generate JavaScript function name from panel name (e.g., 'database' -> 'renderDatabasePanel')
				$functionName = 'render' . ucfirst($panel->getName()) . 'Panel';
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
		 * Generate the complete HTML output for the debug bar
		 *
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
			foreach ($jsTemplates as $panelName => $template) {
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
<!-- Canvas Debug Bar -->
<div id="canvas-debug-bar" class="canvas-debug-bar minimized">
    <!-- Header with logo and statistics -->
    <div class="canvas-debug-bar-header" onclick="CanvasDebugBar.toggle()">
        <div class="canvas-debug-bar-logo">Canvas Debug</div>
        <div class="canvas-debug-bar-stats" id="debug-stats"></div>
    </div>
    
    <!-- Main content area with tabs and panels -->
    <div class="canvas-debug-bar-content">
        <div class="canvas-debug-bar-tabs" id="debug-tabs"></div>
        <div class="canvas-debug-bar-panels" id="debug-panels"></div>
    </div>
</div>

<style>
	{$this->getBaseCss()}
	{$cssContent}
</style>

<script>
	{$this->getBaseJs()}
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
		 *
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
    transition: all 0.3s ease;
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
		 * Get the base JavaScript functionality for the debug bar
		 *
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
 */
window.CanvasDebugBar = {
    data: null,
    
    /**
     * Initialize the debug bar with data from the server
     *
     * @param {Object} debugData Data containing stats, panels, and templates
     */
    init: function(debugData) {
        this.data = debugData;
        this.renderStats();
        this.renderTabs();
        this.renderPanels();
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
        debugBar.classList.toggle('minimized');
    },
    
    /**
     * Switch to a specific tab/panel
     *
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
     *
     * @param {string} key The statistic key to format
     * @return {string} Formatted label
     */
    formatStatLabel: function(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    },
    
    /**
     * Escape HTML characters to prevent XSS
     *
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