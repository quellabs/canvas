<?php
	
	namespace Quellabs\Canvas\Inspector\Panels;
	
	use Quellabs\Contracts\Inspector\EventCollectorInterface;
	use Quellabs\Contracts\Inspector\InspectorPanelInterface;
	use Symfony\Component\HttpFoundation\Request;
	
	/**
	 * WakaPAC Message Spy Panel for Canvas Inspector
	 *
	 * Installs a WakaPAC message hook to intercept all PAC messages client-side
	 * before they reach their target container's msgProc.
	 *
	 * Operates in two modes:
	 *
	 *   Live mode    — always-on ring buffer showing the last N messages.
	 *                  Useful for a quick glance at recent activity without
	 *                  any explicit user action.
	 *
	 *   Capture mode — explicit start/stop collection into an unbounded list,
	 *                  useful for reproducing a specific interaction sequence.
	 *                  The captured list remains frozen after stopping so the
	 *                  user can inspect it without it scrolling away.
	 *
	 * Because all data originates client-side, PHP is only responsible for
	 * delivering the panel structure and JavaScript. No server-side event
	 * collection is involved — getSignalPatterns() and processEvents() are no-ops.
	 *
	 * @package Quellabs\Canvas\Inspector\Panels
	 */
	class WakaPACPanel implements InspectorPanelInterface {
		
		/**
		 * Number of messages retained in the live ring buffer.
		 * Older entries are silently discarded as new ones arrive.
		 */
		private const int RING_BUFFER_SIZE = 8;
	
		/**
		 * This panel does not listen to any server-side signals.
		 * All data is collected client-side via the WakaPAC hook.
		 * @return array
		 */
		public function getSignalPatterns(): array {
			return [];
		}
		
		/**
		 * No server-side events to process — all message data is client-side.
		 * @return void
		 */
		public function processEvents(): void {}
		
		/**
		 * @return string
		 */
		public function getName(): string {
			return 'wakapac';
		}
		
		/**
		 * @return string
		 */
		public function getTabLabel(): string {
			return 'WakaPAC Spy';
		}
		
		/**
		 * @return string
		 */
		public function getIcon(): string {
			return '📨';
		}
		
		/**
		 * No server-side data to provide.
		 * Returns panel configuration consumed by the JS template as initial state.
		 * @param Request $request
		 * @return array
		 */
		public function getData(Request $request): array {
			return [
				'ringBufferSize' => self::RING_BUFFER_SIZE,
			];
		}
		
		/**
		 * Message counts are tracked client-side only.
		 * The JS template updates the counter directly via DOM manipulation.
		 * @return array
		 */
		public function getStats(): array {
			return [];
		}
		
		/**
		 * Returns a JavaScript function body that:
		 *   1. Defines WakaPACPanel — a self-contained object holding all state and behaviour
		 *   2. Defers initPanel() via setTimeout until Registry has inserted the HTML into the DOM
		 *   3. Returns the initial panel HTML string (required by Registry.renderPanels)
		 *
		 * Execution context: Registry wraps this code in
		 *   window.renderWakapacPanel = function(data) { ... }
		 * and calls it during DOMContentLoaded. The return value is inserted via innerHTML,
		 * which is why the DOM nodes don't exist yet when the function body runs.
		 *
		 * Note: Registry wraps the returned HTML in <div id="panel-wakapac"> automatically.
		 * Do not add that wrapper here — it would result in a duplicate ID in the DOM.
		 *
		 * @return string JavaScript function body
		 */
		public function getJsTemplate(): string {
			$ringBufferSize = self::RING_BUFFER_SIZE;
			
			return <<<JS

const RING_BUFFER_SIZE = {$ringBufferSize};

/**
 * Self-contained WakaPAC message spy panel controller.
 *
 * Defined as a local object literal to avoid polluting the global scope.
 * All state and behaviour are encapsulated here — no free-floating functions
 * or variables escape to window.
 *
 * Lifecycle:
 *   init(panelEl)  — called once after the panel HTML is in the DOM.
 *                    Installs the WakaPAC hook and wires up UI controls.
 *   refresh()      — called after every state change to re-render the table,
 *                    mode label, capture button and counter.
 */
const WakaPACPanel = {

    // ── State ─────────────────────────────────────────────────────────────────

    /** @type {Array}    Ring buffer — always holds the last RING_BUFFER_SIZE messages */
    ringBuffer: [],

    /** @type {Array}    Capture buffer — populated only during an active capture session */
    captureBuffer: [],

    /** @type {boolean}  True while a capture session is active */
    isCapturing: false,

    /** @type {number|null}  Hook handle returned by installMessageHook(), used for cleanup */
    hhook: null,

    /** @type {number}   Running total of all messages seen since the page loaded */
    totalSeen: 0,

    /** @type {Object}   Reverse map from numeric message id → MSG_* constant name */
    messageNames: {},

    /** @type {HTMLElement|null}  Cached reference to the outer panel element */
    panelEl: null,

    // ── Initialisation ────────────────────────────────────────────────────────

    /**
     * Wires up the WakaPAC hook and panel UI controls.
     * Called once, after the panel HTML has been inserted into the DOM.
     * @param {HTMLElement} panelEl  The outer #panel-wakapac element
     */
    init(panelEl) {
        this.panelEl = panelEl;

        // Guard: wakaPAC must be present and the hook API must exist
        if (typeof wakaPAC === 'undefined' || typeof wakaPAC.installMessageHook !== 'function') {
            const tbody = panelEl.querySelector('.wakapac-tbody');

            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="5" class="wakapac-empty wakapac-error">'
                    + 'wakaPAC not found — panel inactive'
                    + '</td></tr>';
            }

            return;
        }

        // Build the reverse map from the MSG_* constants exported on wakaPAC.
        // Constructed here (not at module level) to guarantee wakaPAC is initialised.
        // Any future MSG_* constants added to wakaPAC appear here automatically.
        this.messageNames = Object.fromEntries(
            Object.entries(wakaPAC)
                .filter(([key]) => key.startsWith('MSG_'))
                .map(([key, value]) => [value, key])
        );

        // Install the message hook.
        // Equivalent to Win32 WH_CALLWNDPROC: fires before msgProc receives the message.
        // Arrow function preserves `this` so the hook body can access panel state.
        this.hhook = wakaPAC.installMessageHook((event, callNextHook) => {
            const entry = {
                // HH:MM:SS.mmm — readable timestamp without the date component
                time:    new Date().toISOString().substr(11, 12),
                // Resolve the container's pac-id; fall back to em-dash when unavailable
                pacId:   event.target?.getAttribute?.('data-pac-id') ?? '—',
                message: event.message,
                wParam:  event.wParam,
                lParam:  event.lParam,
            };

            // Always update the ring buffer, evicting the oldest entry when full
            this.ringBuffer.push(entry);

            if (this.ringBuffer.length > RING_BUFFER_SIZE) {
                this.ringBuffer.shift();
            }

            // Additionally append to the capture buffer during an active session
            if (this.isCapturing) {
                this.captureBuffer.push(entry);
            }

            this.totalSeen++;
            this.refresh();

            // Pass the message through — spy hooks never swallow
            callNextHook();
        });

        // Capture button: toggle between live and capture mode
        panelEl.querySelector('.wakapac-btn-capture')?.addEventListener('click', () => {
            if (this.isCapturing) {
                // Stop: freeze the capture list so the user can inspect it without it scrolling
                this.isCapturing = false;
            } else {
                // Start: discard the previous capture and begin collecting fresh
                this.captureBuffer = [];
                this.isCapturing   = true;
            }

            this.refresh();
        });

        // Clear button: wipes whichever buffer is currently displayed
        panelEl.querySelector('.wakapac-btn-clear')?.addEventListener('click', () => {
            if (this.isCapturing) {
                this.captureBuffer = [];
            } else {
                this.ringBuffer.length = 0;
            }

            this.totalSeen = 0;
            this.refresh();
        });

        this.refresh();
    },

    // ── Rendering ─────────────────────────────────────────────────────────────

    /**
     * Full panel refresh: table, mode label, capture button state, counter.
     * Called after every state mutation.
     */
    refresh() {
        const entries = this.isCapturing ? this.captureBuffer : this.ringBuffer;
        this.renderTable(entries);
        this.updateCaptureButton();
        this.updateModeLabel();
        this.updateCounter();
    },

    /**
     * Re-renders the message tbody with the given entries.
     * Shows a placeholder row when the list is empty.
     * @param {Array} entries
     */
    renderTable(entries) {
        const tbody = this.panelEl.querySelector('.wakapac-tbody');
        if (!tbody) return;

        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="wakapac-empty">No messages yet</td></tr>';
            return;
        }

        tbody.innerHTML = entries.map((e, i) => this.renderMessageRow(e, i)).join('');
    },

    /**
     * Builds the HTML for a single message row.
     * Alternating row classes provide visual separation without borders.
     * @param {Object} entry
     * @param {number} index
     * @returns {string}
     */
    renderMessageRow(entry, index) {
        const rowClass = index % 2 === 0 ? 'wakapac-row-even' : 'wakapac-row-odd';
        return '<tr class="' + rowClass + '">'
            + '<td class="wakapac-cell wakapac-cell-time">'  + escapeHtml(entry.time)                          + '</td>'
            + '<td class="wakapac-cell wakapac-cell-pac">'   + escapeHtml(entry.pacId)                         + '</td>'
            + '<td class="wakapac-cell wakapac-cell-msg">'   + escapeHtml(this.formatMessageId(entry.message)) + '</td>'
            + '<td class="wakapac-cell wakapac-cell-param">' + escapeHtml(this.formatParam(entry.wParam))      + '</td>'
            + '<td class="wakapac-cell wakapac-cell-param">' + escapeHtml(this.formatParam(entry.lParam))      + '</td>'
            + '</tr>';
    },

    /**
     * Updates the capture button label and active state to reflect current mode.
     */
    updateCaptureButton() {
        const btn = this.panelEl.querySelector('.wakapac-btn-capture');
        if (!btn) return;
        btn.textContent = this.isCapturing ? '⏹ Stop' : '⏺ Capture';
        btn.classList.toggle('wakapac-btn-active', this.isCapturing);
    },

    /**
     * Updates the mode label to reflect live vs. capture mode.
     */
    updateModeLabel() {
        const label = this.panelEl.querySelector('.wakapac-mode-label');
        if (!label) return;
        label.textContent = this.isCapturing
            ? 'Capturing'
            : 'Live (last ' + RING_BUFFER_SIZE + ')';
    },

    /**
     * Updates the total-seen counter in the toolbar.
     */
    updateCounter() {
        const counter = this.panelEl.querySelector('.wakapac-counter');
        if (counter) counter.textContent = this.totalSeen;
    },

    // ── Formatters ────────────────────────────────────────────────────────────

    /**
     * Formats a numeric message id as "MSG_LBUTTONDOWN (0x0201)".
     * Falls back to MSG_UNKNOWN for ids not present in the reverse map.
     * @param {number} id
     * @returns {string}
     */
    formatMessageId(id) {
        const name = this.messageNames[id] ?? 'MSG_UNKNOWN';
        const hex  = '0x' + id.toString(16).toUpperCase().padStart(4, '0');
        return name + ' (' + hex + ')';
    },

    /**
     * Formats a wParam or lParam value as signed decimal with hex annotation.
     * Zero is displayed as plain '0' without redundant annotation.
     * @param {number} value
     * @returns {string}
     */
    formatParam(value) {
        if (value === 0) return '0';
        const hex = '0x' + (value >>> 0).toString(16).toUpperCase().padStart(8, '0');
        return value + ' (' + hex + ')';
    },
};

// ── Deferred initialisation ───────────────────────────────────────────────────

// Registry inserts the template return value via innerHTML, so the DOM nodes
// don't exist yet at the moment this function executes. setTimeout(0) defers
// WakaPACPanel.init() until after the current call stack (renderPanels) completes.
setTimeout(function() {
    const panelEl = document.getElementById('panel-wakapac');
    if (panelEl) WakaPACPanel.init(panelEl);
}, 0);

// ── Initial HTML ──────────────────────────────────────────────────────────────

// Returned to Registry.renderPanels() which wraps it in:
//   <div id="panel-wakapac" class="canvas-debug-bar-panel">
// Do not repeat that wrapper here — it would produce a duplicate ID in the DOM.
return `
    <div class="wakapac-inner">

        <div class="wakapac-toolbar">
            <div class="wakapac-toolbar-left">
                <span class="wakapac-mode-label">Live (last {$ringBufferSize})</span>
                &nbsp;·&nbsp;
                <span class="wakapac-counter">0</span>&nbsp;messages seen
            </div>
            <div class="wakapac-toolbar-right">
                <button class="wakapac-btn wakapac-btn-capture">⏺ Capture</button>
                <button class="wakapac-btn wakapac-btn-clear">🗑 Clear</button>
            </div>
        </div>

        <div class="wakapac-table-wrapper">
            <table class="wakapac-table">
                <thead>
                    <tr>
                        <th class="wakapac-th">Time</th>
                        <th class="wakapac-th">Container</th>
                        <th class="wakapac-th">Message</th>
                        <th class="wakapac-th">wParam</th>
                        <th class="wakapac-th">lParam</th>
                    </tr>
                </thead>
                <tbody class="wakapac-tbody">
                    <tr><td colspan="5" class="wakapac-empty">Waiting for messages…</td></tr>
                </tbody>
            </table>
        </div>

    </div>
`;
JS;
		}
		
		/**
		 * Panel-scoped CSS. All selectors are prefixed with #panel-wakapac to
		 * prevent styles from leaking into other panels or the host page.
		 * @return string
		 */
		public function getCss(): string {
			return <<<CSS

/* ── Layout ── */
#panel-wakapac .wakapac-inner {
    display: flex;
    flex-direction: column;
    height: 100%;
}

/* ── Toolbar ── */
#panel-wakapac .wakapac-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 12px;
    border-bottom: 1px solid #dee2e6;
    background: #f8f9fa;
    flex-shrink: 0;
    font-size: 12px;
    color: #6c757d;
}

#panel-wakapac .wakapac-toolbar-left {
    display: flex;
    align-items: center;
}

#panel-wakapac .wakapac-toolbar-right {
    display: flex;
    gap: 6px;
}

#panel-wakapac .wakapac-mode-label {
    font-weight: 600;
    color: #495057;
}

#panel-wakapac .wakapac-counter {
    font-weight: 700;
    color: #0d6efd;
}

/* ── Buttons ── */
#panel-wakapac .wakapac-btn {
    padding: 3px 10px;
    font-size: 11px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    background: #fff;
    cursor: pointer;
    color: #495057;
    transition: background 0.15s, border-color 0.15s;
}

#panel-wakapac .wakapac-btn:hover {
    background: #e9ecef;
    border-color: #adb5bd;
}

#panel-wakapac .wakapac-btn-active {
    background: #dc3545;
    border-color: #dc3545;
    color: #fff;
}

#panel-wakapac .wakapac-btn-active:hover {
    background: #bb2d3b;
    border-color: #bb2d3b;
}

/* ── Table ── */
#panel-wakapac .wakapac-table-wrapper {
    flex: 1;
    overflow-y: auto;
}

#panel-wakapac .wakapac-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
    font-family: monospace;
}

#panel-wakapac .wakapac-th {
    position: sticky;
    top: 0;
    background: #e9ecef;
    padding: 5px 10px;
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    color: #495057;
    border-bottom: 2px solid #dee2e6;
    white-space: nowrap;
}

#panel-wakapac .wakapac-cell {
    padding: 3px 10px;
    border-bottom: 1px solid #f1f3f5;
    white-space: nowrap;
    vertical-align: middle;
}

#panel-wakapac .wakapac-cell-time  { color: #6c757d; width: 95px; }
#panel-wakapac .wakapac-cell-pac   { color: #0d6efd; }
#panel-wakapac .wakapac-cell-msg   { color: #198754; font-weight: 500; }
#panel-wakapac .wakapac-cell-param { color: #6f42c1; }

#panel-wakapac .wakapac-row-even { background: #fff; }
#panel-wakapac .wakapac-row-odd  { background: #f8f9fa; }

#panel-wakapac .wakapac-empty {
    padding: 20px;
    text-align: center;
    color: #adb5bd;
    font-style: italic;
    font-family: sans-serif;
}

#panel-wakapac .wakapac-error {
    color: #dc3545;
}
CSS;
		}
	}