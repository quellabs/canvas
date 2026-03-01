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
		 * No server-side events to process — all message data is client-side.
		 * @return void
		 */
		public function processEvents(EventCollectorInterface $collector): void {}
		
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
		 *   2. Defers init() via setTimeout until Registry has inserted the HTML into the DOM
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

    /** @type {Array}         Ring buffer — always holds the last RING_BUFFER_SIZE messages */
    ringBuffer: [],

    /** @type {Array}         Capture buffer — populated only during an active capture session */
    captureBuffer: [],

    /** @type {boolean}       True while a capture session is active */
    isCapturing: false,

    /**
     * Which tab is currently visible: 'live' or 'recording'.
     * Switches to 'recording' automatically when recording starts so the user
     * can watch messages arrive in real time. Stays on 'recording' after stop
     * so the frozen data remains accessible while the live buffer keeps rolling.
     * @type {string}
     */
    activeTab: 'live',

    /** @type {number|null}   Hook handle returned by installMessageHook(), used for cleanup */
    hhook: null,

    /** @type {number}        Running total of all messages seen since the page loaded */
    totalSeen: 0,

    /** @type {Object}        Reverse map from numeric message id to MSG_* constant name */
    messageNames: {},

    /**
     * Message types collapsed into a single row with a repeat counter when
     * consecutive identical messages arrive for the same container.
     * Populated in init() once wakaPAC constants are available.
     * @type {Set<number>}
     */
    collapsibleMessages: new Set(),

    /**
     * Filter state — one boolean per category key.
     * true = show messages of this category, false = hide them.
     * Move and Timer start off by default; all others start on.
     * Messages not belonging to any category (MSG_USER+) are always shown.
     * @type {Object<string,boolean>}
     */
    filters: {
        mouse: true,
        move:  false,
        key:   true,
        focus: true,
        timer: false,
        wheel: false,
        drag:  true,
        input: true,
        size:  true,
    },

    /**
     * Maps each filter category key to the set of message type constants it covers.
     * Populated in init() after wakaPAC constants are available.
     * @type {Object<string,Set<number>>}
     */
    filterCategories: {},

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

        // High-frequency message types that are collapsed into a single row
        // with a repeat counter instead of flooding the table.
        // When a different message type arrives, the counter resets.
        this.collapsibleMessages = new Set([
            wakaPAC.MSG_MOUSEMOVE,
            wakaPAC.MSG_TIMER,
            wakaPAC.MSG_MOUSEWHEEL,
        ]);

        // Map each filter category to the exact set of message types it covers.
        // Messages that don't appear in any category (custom MSG_USER+) are always shown.
        this.filterCategories = {
            mouse: new Set([
                wakaPAC.MSG_LBUTTONDOWN, wakaPAC.MSG_LBUTTONUP, wakaPAC.MSG_LCLICK, wakaPAC.MSG_LBUTTONDBLCLK,
                wakaPAC.MSG_RBUTTONDOWN, wakaPAC.MSG_RBUTTONUP, wakaPAC.MSG_RCLICK,
                wakaPAC.MSG_MBUTTONDOWN, wakaPAC.MSG_MBUTTONUP, wakaPAC.MSG_MCLICK,
                wakaPAC.MSG_MOUSEENTER,  wakaPAC.MSG_MOUSELEAVE,
                wakaPAC.MSG_MOUSEENTER_DESCENDANT, wakaPAC.MSG_MOUSELEAVE_DESCENDANT,
                wakaPAC.MSG_CAPTURECHANGED,
            ]),
            move:  new Set([ wakaPAC.MSG_MOUSEMOVE ]),
            key:   new Set([ wakaPAC.MSG_KEYDOWN, wakaPAC.MSG_KEYUP, wakaPAC.MSG_CHAR ]),
            focus: new Set([ wakaPAC.MSG_SETFOCUS, wakaPAC.MSG_KILLFOCUS ]),
            timer: new Set([ wakaPAC.MSG_TIMER ]),
            wheel: new Set([ wakaPAC.MSG_MOUSEWHEEL ]),
            drag:  new Set([ wakaPAC.MSG_DRAGENTER, wakaPAC.MSG_DRAGOVER, wakaPAC.MSG_DRAGLEAVE, wakaPAC.MSG_DROP ]),
            input: new Set([ wakaPAC.MSG_CHANGE, wakaPAC.MSG_INPUT, wakaPAC.MSG_INPUT_COMPLETE, wakaPAC.MSG_SUBMIT, wakaPAC.MSG_COPY, wakaPAC.MSG_PASTE ]),
            size:  new Set([ wakaPAC.MSG_SIZE, wakaPAC.MSG_GESTURE ]),
        };

        // Install the message hook.
        // Equivalent to Win32 WH_CALLWNDPROC: fires before msgProc receives the message.
        // Arrow function preserves `this` so the hook body can access panel state.
        this.hhook = wakaPAC.installMessageHook((event, callNextHook) => {
            // Drop the message immediately if its category is filtered out.
            // Filtering at intake means the buffer only ever contains messages
            // the user actually wants to see.
            if (!this.isVisible(event.message)) {
                callNextHook();
                return;
            }

            const entry = {
                // HH:MM:SS.mmm — readable timestamp without the date component
                time:    new Date().toISOString().substr(11, 12),
                // pac-id of the container this message is dispatched to
                pacId:   event.pacId ?? '—',
                message: event.message,
                wParam:  event.wParam,
                lParam:  event.lParam,
                // The DOM element that originated the event — may be a descendant
                // of the container (e.g. a <button> inside a PAC container).
                // Stored as a reference; formatting happens at render time.
                target:  event.target ?? null,
                // Repeat counter — incremented when consecutive identical collapsible
                // messages arrive for the same container instead of pushing a new row.
                count:   1,
            };

            this.pushEntry(this.ringBuffer, entry, RING_BUFFER_SIZE);

            if (this.isCapturing) {
                this.pushEntry(this.captureBuffer, entry, Infinity);
            }

            this.totalSeen++;
            this.refresh();

            // Pass the message through — spy hooks never swallow
            callNextHook();
        });

        // Wire up filter toggle buttons — each button carries a data-filter attribute
        // matching a key in this.filters. Clicking toggles the filter and re-renders.
        panelEl.querySelectorAll('.wakapac-filter-btn').forEach(btn => {
            const category = btn.getAttribute('data-filter');

            // Apply initial active state to reflect the default filter values
            btn.classList.toggle('wakapac-filter-btn-active', this.filters[category] === true);

            btn.addEventListener('click', () => {
                this.filters[category] = !this.filters[category];
                btn.classList.toggle('wakapac-filter-btn-active', this.filters[category]);
                this.refresh();
            });
        });

        // Wire up tab buttons
        panelEl.querySelectorAll('.wakapac-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                this.activeTab = tab.getAttribute('data-tab');
                this.refresh();
            });
        });

        // Record button: start/stop a recording session.
        // Starting switches to the Recording tab so the user can watch messages
        // arrive live. Stopping freezes the tab — data persists until next record.
        panelEl.querySelector('.wakapac-btn-capture')?.addEventListener('click', () => {
            if (this.isCapturing) {
                this.isCapturing = false;
            } else {
                this.captureBuffer = [];
                this.isCapturing   = true;
                this.activeTab     = 'recording'; // switch to recording tab on start
            }

            this.refresh();
        });

        // Clear button: wipes the active tab's buffer
        panelEl.querySelector('.wakapac-btn-clear')?.addEventListener('click', () => {
            if (this.activeTab === 'recording') {
                this.captureBuffer = [];
            } else {
                this.ringBuffer.length = 0;
            }

            this.totalSeen = 0;
            this.refresh();
        });

        this.refresh();
    },

    // ── Buffer management ─────────────────────────────────────────────────────

    /**
     * Pushes an entry into a buffer, collapsing it into the previous entry
     * if the message type is collapsible and matches the last entry's type
     * and container. Evicts the oldest entry when the buffer exceeds maxSize.
     *
     * Collapsing updates wParam/lParam to the latest values so the most recent
     * state (e.g. mouse position) is always shown, while count reflects how
     * many events were received since the last non-collapsible message.
     *
     * @param {Array}  buffer   Ring or capture buffer to push into
     * @param {Object} entry    The new entry to push or merge
     * @param {number} maxSize  Maximum buffer length before eviction
     */
    pushEntry(buffer, entry, maxSize) {
        const last = buffer[buffer.length - 1];

        // Collapse into the previous row if:
        //   - the message type is in the collapsible set
        //   - the previous entry has the same message type and container
        if (
            last &&
            this.collapsibleMessages.has(entry.message) &&
            last.message === entry.message &&
            last.pacId   === entry.pacId
        ) {
            last.count++;
            last.wParam = entry.wParam; // update to most recent (e.g. mouse position)
            last.lParam = entry.lParam;
            last.time   = entry.time;   // update timestamp to most recent occurrence
            return;
        }

        buffer.push(entry);

        if (buffer.length > maxSize) {
            buffer.shift();
        }
    },

    // ── Filtering ─────────────────────────────────────────────────────────────

    /**
     * Returns true if the given message type should be buffered given the
     * current filter state. Called at hook intake — messages that return false
     * are dropped before they reach the buffer.
     *
     * Messages that don't belong to any known category (MSG_USER+ custom messages)
     * are always accepted — they are intentional application-level dispatches.
     *
     * @param {number} message
     * @returns {boolean}
     */
    isVisible(message) {
        for (const [category, messageSet] of Object.entries(this.filterCategories)) {
            if (messageSet.has(message)) {
                return this.filters[category] === true;
            }
        }

        // Not in any category — always show (custom/user messages)
        return true;
    },

    // ── Rendering ─────────────────────────────────────────────────────────────

    /**
     * Full panel refresh: tabs, table, capture button state, counter.
     * Called after every state mutation.
     */
    refresh() {
        const entries = this.activeTab === 'recording' ? this.captureBuffer : this.ringBuffer;
        this.updateTabs();
        this.renderTable(entries);
        this.updateCaptureButton();
        this.updateCounter();
    },

    /**
     * Updates tab active states and their message count badges.
     */
    updateTabs() {
        this.panelEl.querySelectorAll('.wakapac-tab').forEach(tab => {
            const name    = tab.getAttribute('data-tab');
            const isActive = name === this.activeTab;
            tab.classList.toggle('wakapac-tab-active', isActive);

            // Show message count in the Recording tab label
            const badge = tab.querySelector('.wakapac-tab-count');

            if (badge) {
                if (name === 'recording') {
                    badge.textContent = this.captureBuffer.length > 0
                        ? ' (' + this.captureBuffer.length + ')'
                        : '';
                    // Pulse red while recording is active
                    badge.classList.toggle('is-recording', this.isCapturing);
                }
            }
        });
    },

    /**
     * Re-renders the message tbody with the given entries.
     * Shows a placeholder row when no entries are present.
     * @param {Array} entries
     */
    renderTable(entries) {
        const tbody = this.panelEl.querySelector('.wakapac-tbody');
        if (!tbody) { return; }

        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="wakapac-empty">No messages yet</td></tr>';
            return;
        }

        tbody.innerHTML = entries.map((e, i) => this.renderMessageRow(e, i)).join('');
    },

    /**
     * Builds the HTML for a single message row.
     * Alternating row classes provide visual separation without borders.
     * Collapsed high-frequency messages show a count badge after the message name.
     * @param {Object} entry
     * @param {number} index
     * @returns {string}
     */
    renderMessageRow(entry, index) {
        const rowClass   = index % 2 === 0 ? 'wakapac-row-even' : 'wakapac-row-odd';
        const countBadge = entry.count > 1
            ? ' <span class="wakapac-count-badge">x' + entry.count + '</span>'
            : '';

        return '<tr class="' + rowClass + '">'
            + '<td class="wakapac-cell wakapac-cell-time">'    + escapeHtml(entry.time)                                                    + '</td>'
            + '<td class="wakapac-cell wakapac-cell-pac">'     + escapeHtml(entry.pacId)                                                   + '</td>'
            + '<td class="wakapac-cell wakapac-cell-msg">'     + escapeHtml(this.formatMessageId(entry.message)) + countBadge             + '</td>'
            + '<td class="wakapac-cell wakapac-cell-target">'  + escapeHtml(this.formatTarget(entry.target))                              + '</td>'
            + '<td class="wakapac-cell wakapac-cell-details">' + escapeHtml(this.formatDetails(entry.message, entry.wParam, entry.lParam)) + '</td>'
            + '</tr>';
    },

    /**
     * Updates the capture button label and active state to reflect current mode.
     */
    updateCaptureButton() {
        const btn = this.panelEl.querySelector('.wakapac-btn-capture');
        if (!btn) { return; }
        btn.textContent = this.isCapturing ? '⏹ Stop' : '⏺ Record';
        btn.classList.toggle('wakapac-btn-active', this.isCapturing);
    },

    /**
     * Updates the total-seen counter in the toolbar.
     */
    updateCounter() {
        const counter = this.panelEl.querySelector('.wakapac-counter');
        if (counter) { counter.textContent = this.totalSeen; }
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
     * Formats a DOM element reference into a concise human-readable descriptor.
     * Shows the tag name, id (if present), or first class (if present).
     * Returns em-dash when the target is the container itself (redundant with
     * the Container column) or when no target element is available.
     *
     * Examples:
     *   <button id="submit">        =>  "button#submit"
     *   <span class="icon active">  =>  "span.icon"
     *   <input type="text">         =>  "input"
     *   <div data-pac-id="...">     =>  "—"
     *
     * @param {Element|null} target
     * @returns {string}
     */
    formatTarget(target) {
        if (!target || !(target instanceof Element)) { return '—'; }

        // Target is the container itself — redundant with the Container column
        if (target.hasAttribute('data-pac-id')) { return '—'; }

        const tag = target.tagName.toLowerCase();

        // Prefer id — more specific and stable than class names
        if (target.id) {
            return tag + '#' + target.id;
        }

        // First non-empty class as a secondary identifier
        const firstClass = Array.from(target.classList).find(c => c.length > 0);

        if (firstClass) {
            return tag + '.' + firstClass;
        }

        return tag;
    },

    /**
     * Dispatches wParam/lParam decoding to a message-type-specific formatter.
     * Returns a human-readable details string for the Details column, replacing
     * the raw wParam/lParam hex values that were shown previously.
     * Falls back to raw hex for unknown or custom messages (MSG_USER+).
     * @param {number} message
     * @param {number} wParam
     * @param {number} lParam
     * @returns {string}
     */
    formatDetails(message, wParam, lParam) {
        switch (message) {
            case wakaPAC.MSG_MOUSEMOVE:
            case wakaPAC.MSG_LBUTTONDOWN:
            case wakaPAC.MSG_LBUTTONUP:
            case wakaPAC.MSG_LBUTTONDBLCLK:
            case wakaPAC.MSG_LCLICK:
            case wakaPAC.MSG_RBUTTONDOWN:
            case wakaPAC.MSG_RBUTTONUP:
            case wakaPAC.MSG_RCLICK:
            case wakaPAC.MSG_MBUTTONDOWN:
            case wakaPAC.MSG_MBUTTONUP:
            case wakaPAC.MSG_MCLICK:
            case wakaPAC.MSG_MOUSEENTER:
            case wakaPAC.MSG_MOUSELEAVE:
            case wakaPAC.MSG_MOUSEENTER_DESCENDANT:
            case wakaPAC.MSG_MOUSELEAVE_DESCENDANT:
            case wakaPAC.MSG_DRAGENTER:
            case wakaPAC.MSG_DRAGOVER:
            case wakaPAC.MSG_DRAGLEAVE:
            case wakaPAC.MSG_DROP:
                return this.formatMouseDetails(wParam, lParam);

            case wakaPAC.MSG_MOUSEWHEEL:
                return this.formatMouseWheelDetails(wParam, lParam);

            case wakaPAC.MSG_KEYDOWN:
            case wakaPAC.MSG_KEYUP:
                return this.formatKeyDetails(wParam, lParam);

            case wakaPAC.MSG_CHAR:
                return this.formatCharDetails(wParam);

            case wakaPAC.MSG_SIZE:
                return this.formatSizeDetails(wParam, lParam);

            case wakaPAC.MSG_TIMER:
                return 'timerId=' + wParam;

            case wakaPAC.MSG_GESTURE:
                return this.formatGestureDetails(wParam, lParam);

            case wakaPAC.MSG_SETFOCUS:
            case wakaPAC.MSG_KILLFOCUS:
            case wakaPAC.MSG_SUBMIT:
            case wakaPAC.MSG_COPY:
            case wakaPAC.MSG_PASTE:
            case wakaPAC.MSG_CAPTURECHANGED:
            case wakaPAC.MSG_CHANGE:
            case wakaPAC.MSG_INPUT:
            case wakaPAC.MSG_INPUT_COMPLETE:
                // No meaningful wParam/lParam for these messages
                return '—';

            default:
                // Unknown or custom message (MSG_USER+) — show raw values as fallback
                return 'wParam=0x' + (wParam >>> 0).toString(16).toUpperCase().padStart(8, '0')
                    + ' lParam=0x' + (lParam >>> 0).toString(16).toUpperCase().padStart(8, '0');
        }
    },

    /**
     * Decodes mouse message wParam/lParam into readable coordinates and modifiers.
     *
     * wParam is a bitmask of modifier/button states (MK_* flags):
     *   bit 0 = MK_LBUTTON, bit 1 = MK_RBUTTON, bit 2 = MK_MBUTTON
     *   bit 3 = MK_SHIFT,   bit 4 = MK_CONTROL,  bit 5 = MK_ALT
     *
     * lParam encodes cursor position as two packed 16-bit signed integers:
     *   low word  = x coordinate (client space)
     *   high word = y coordinate (client space)
     *
     * @param {number} wParam
     * @param {number} lParam
     * @returns {string}
     */
    formatMouseDetails(wParam, lParam) {
        // Extract x/y from the two 16-bit halves of lParam.
        // Treat as signed (<<16>>16) to handle negative coordinates
        // (e.g. when the cursor is outside the viewport during capture).
        const x = (lParam & 0xFFFF) << 16 >> 16;
        const y = (lParam >> 16)    << 16 >> 16;

        // Decode wParam modifier bitmask into named flags
        const modifiers = [];
        if (wParam & wakaPAC.MK_LBUTTON)  { modifiers.push('LButton'); }
        if (wParam & wakaPAC.MK_RBUTTON)  { modifiers.push('RButton'); }
        if (wParam & wakaPAC.MK_MBUTTON)  { modifiers.push('MButton'); }
        if (wParam & wakaPAC.MK_SHIFT)    { modifiers.push('Shift'); }
        if (wParam & wakaPAC.MK_CONTROL)  { modifiers.push('Ctrl'); }
        if (wParam & wakaPAC.MK_ALT)      { modifiers.push('Alt'); }

        const modStr = modifiers.length > 0 ? '  ' + modifiers.join('+') : '';
        return 'x=' + x + ', y=' + y + modStr;
    },

    /**
     * Decodes mousewheel wParam/lParam.
     *
     * wParam high word = signed wheel delta (positive = forward, negative = backward).
     * Each notch of a standard wheel produces ±120 (WHEEL_DELTA).
     * wParam low word  = modifier bitmask (same MK_* flags as mouse messages).
     * lParam           = cursor position, same encoding as other mouse messages.
     *
     * @param {number} wParam
     * @param {number} lParam
     * @returns {string}
     */
    formatMouseWheelDetails(wParam, lParam) {
        // High word of wParam is a signed 16-bit delta
        const delta     = (wParam >> 16) << 16 >> 16;
        const modifiers = wParam & 0xFFFF;

        const x = (lParam & 0xFFFF) << 16 >> 16;
        const y = (lParam >> 16)    << 16 >> 16;

        const mods = [];
        if (modifiers & wakaPAC.MK_SHIFT)   { mods.push('Shift'); }
        if (modifiers & wakaPAC.MK_CONTROL) { mods.push('Ctrl'); }
        if (modifiers & wakaPAC.MK_ALT)     { mods.push('Alt'); }

        const modStr    = mods.length > 0 ? '  ' + mods.join('+') : '';
        const direction = delta > 0 ? '▲' : '▼';
        return direction + ' delta=' + delta + ', x=' + x + ', y=' + y + modStr;
    },

    /**
     * Decodes keyboard message wParam/lParam.
     *
     * wParam = virtual key code (VK_* constant).
     * lParam = modifier bitmask using KM_* flags:
     *   bit 25 = KM_SHIFT, bit 26 = KM_CONTROL, bit 29 = KM_ALT
     *
     * @param {number} wParam
     * @param {number} lParam
     * @returns {string}
     */
    formatKeyDetails(wParam, lParam) {
        const vkName = this.getVkName(wParam);

        const modifiers = [];
        if (lParam & wakaPAC.KM_SHIFT)   { modifiers.push('Shift'); }
        if (lParam & wakaPAC.KM_CONTROL) { modifiers.push('Ctrl'); }
        if (lParam & wakaPAC.KM_ALT)     { modifiers.push('Alt'); }

        const modStr = modifiers.length > 0 ? '  ' + modifiers.join('+') : '';
        return vkName + modStr;
    },

    /**
     * Decodes MSG_CHAR wParam.
     * wParam = Unicode code point of the character typed.
     * @param {number} wParam
     * @returns {string}
     */
    formatCharDetails(wParam) {
        const char = String.fromCodePoint(wParam);
        return 'char="' + char + '" (U+' + wParam.toString(16).toUpperCase().padStart(4, '0') + ')';
    },

    /**
     * Decodes MSG_SIZE wParam/lParam.
     *
     * wParam = sizing type constant (SIZE_RESTORED, SIZE_HIDDEN, SIZE_FULLSCREEN).
     * lParam encodes new element dimensions:
     *   low word  = new width  in pixels
     *   high word = new height in pixels
     *
     * @param {number} wParam
     * @param {number} lParam
     * @returns {string}
     */
    formatSizeDetails(wParam, lParam) {
        const width  =  lParam & 0xFFFF;
        const height = (lParam >> 16) & 0xFFFF;

        const typeNames = {
            [wakaPAC.SIZE_RESTORED]:   'restored',
            [wakaPAC.SIZE_HIDDEN]:     'hidden',
            [wakaPAC.SIZE_FULLSCREEN]: 'fullscreen',
        };

        const typeName = typeNames[wParam] ?? 'unknown(' + wParam + ')';
        return width + 'x' + height + '  ' + typeName;
    },

    /**
     * Decodes MSG_GESTURE wParam/lParam.
     * wParam = gesture type identifier.
     * lParam = packed coordinates (same encoding as mouse messages).
     * @param {number} wParam
     * @param {number} lParam
     * @returns {string}
     */
    formatGestureDetails(wParam, lParam) {
        const x = (lParam & 0xFFFF) << 16 >> 16;
        const y = (lParam >> 16)    << 16 >> 16;
        return 'type=' + wParam + ', x=' + x + ', y=' + y;
    },

    /**
     * Resolves a virtual key code to its VK_* constant name by scanning
     * the exported constants on wakaPAC. The result is cached after first call.
     * Falls back to "VK_0x{hex}" for codes not present in the constants.
     * @param {number} vkCode
     * @returns {string}
     */
    getVkName(vkCode) {
        // Build the VK_* reverse map lazily and cache it on the object
        if (!this._vkNames) {
            this._vkNames = Object.fromEntries(
                Object.entries(wakaPAC)
                    .filter(([key]) => key.startsWith('VK_'))
                    .map(([key, value]) => [value, key])
            );
        }

        return this._vkNames[vkCode] ?? 'VK_0x' + vkCode.toString(16).toUpperCase().padStart(2, '0');
    },
};

// ── Deferred initialisation ───────────────────────────────────────────────────

// Registry inserts the template return value via innerHTML, so the DOM nodes
// don't exist yet at the moment this function executes. setTimeout(0) defers
// WakaPACPanel.init() until after the current call stack (renderPanels) completes.
setTimeout(function() {
    const panelEl = document.getElementById('panel-wakapac');
    if (panelEl) { WakaPACPanel.init(panelEl); }
}, 0);

// ── Initial HTML ──────────────────────────────────────────────────────────────

// Returned to Registry.renderPanels() which wraps it in:
//   <div id="panel-wakapac" class="canvas-debug-bar-panel">
// Do not repeat that wrapper here — it would produce a duplicate ID in the DOM.
return `
    <div class="wakapac-inner">

        <div class="wakapac-toolbar">
            <div class="wakapac-toolbar-left">
                <button class="wakapac-tab wakapac-tab-active" data-tab="live">Live · last {$ringBufferSize}</button>
                <button class="wakapac-tab" data-tab="recording">Recording<span class="wakapac-tab-count"></span></button>
            </div>
            <div class="wakapac-toolbar-right">
                <span class="wakapac-counter">0</span>&nbsp;seen
                <button class="wakapac-btn wakapac-btn-capture">⏺ Record</button>
                <button class="wakapac-btn wakapac-btn-clear">🗑 Clear</button>
            </div>
        </div>

        <div class="wakapac-filterbar">
            <span class="wakapac-filter-label">Show:</span>
            <button class="wakapac-filter-btn" data-filter="mouse" title="Mouse buttons, clicks, enter/leave">🖱 Mouse</button>
            <button class="wakapac-filter-btn" data-filter="move"  title="MSG_MOUSEMOVE">💨 Move</button>
            <button class="wakapac-filter-btn" data-filter="wheel" title="MSG_MOUSEWHEEL">〰 Wheel</button>
            <button class="wakapac-filter-btn" data-filter="key"   title="Keydown, keyup, char">⌨ Key</button>
            <button class="wakapac-filter-btn" data-filter="focus" title="Setfocus, killfocus">🎯 Focus</button>
            <button class="wakapac-filter-btn" data-filter="timer" title="MSG_TIMER">⏱ Timer</button>
            <button class="wakapac-filter-btn" data-filter="drag"  title="Drag enter/over/leave/drop">↕ Drag</button>
            <button class="wakapac-filter-btn" data-filter="input" title="Change, input, submit, copy, paste">✉ Input</button>
            <button class="wakapac-filter-btn" data-filter="size"  title="MSG_SIZE, MSG_GESTURE">⤡ Size</button>
        </div>

        <div class="wakapac-table-wrapper">
            <table class="wakapac-table">
                <thead>
                    <tr>
                        <th class="wakapac-th">Time</th>
                        <th class="wakapac-th">Container</th>
                        <th class="wakapac-th">Message</th>
                        <th class="wakapac-th">Target</th>
                        <th class="wakapac-th">Details</th>
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
    padding: 0 12px 0 0;
    border-bottom: 1px solid #dee2e6;
    background: #f8f9fa;
    flex-shrink: 0;
    font-size: 12px;
    color: #6c757d;
}

#panel-wakapac .wakapac-toolbar-left {
    display: flex;
    align-items: stretch;
}

#panel-wakapac .wakapac-toolbar-right {
    display: flex;
    align-items: center;
    gap: 6px;
}

/* ── Tabs ── */
#panel-wakapac .wakapac-tab {
    padding: 7px 14px;
    font-size: 11px;
    font-weight: 600;
    border: none;
    border-right: 1px solid #dee2e6;
    border-bottom: 2px solid transparent;
    background: transparent;
    cursor: pointer;
    color: #6c757d;
    transition: color 0.15s, border-color 0.15s, background 0.15s;
    white-space: nowrap;
}

#panel-wakapac .wakapac-tab:hover {
    color: #495057;
    background: #e9ecef;
}

#panel-wakapac .wakapac-tab-active {
    color: #0d6efd;
    border-bottom-color: #0d6efd;
    background: #fff;
}

#panel-wakapac .wakapac-tab-count {
    font-weight: 400;
    color: #6c757d;
}

#panel-wakapac .wakapac-tab-count.is-recording {
    color: #dc3545;
    font-weight: 700;
}

#panel-wakapac .wakapac-counter {
    font-weight: 700;
    color: #0d6efd;
    font-size: 11px;
}

/* ── Filter bar ── */
#panel-wakapac .wakapac-filterbar {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 5px 12px;
    border-bottom: 1px solid #dee2e6;
    background: #f8f9fa;
    flex-shrink: 0;
    flex-wrap: wrap;
}

#panel-wakapac .wakapac-filter-label {
    font-size: 11px;
    color: #6c757d;
    margin-right: 2px;
    white-space: nowrap;
}

#panel-wakapac .wakapac-filter-btn {
    padding: 2px 8px;
    font-size: 11px;
    border: 1px solid #ced4da;
    border-radius: 10px;
    background: #fff;
    cursor: pointer;
    color: #6c757d;
    transition: background 0.15s, border-color 0.15s, color 0.15s;
    white-space: nowrap;
}

#panel-wakapac .wakapac-filter-btn:hover {
    background: #e9ecef;
    border-color: #adb5bd;
    color: #495057;
}

/* Active filter buttons use a filled style to indicate "on" */
#panel-wakapac .wakapac-filter-btn-active {
    background: #0d6efd;
    border-color: #0d6efd;
    color: #fff;
}

#panel-wakapac .wakapac-filter-btn-active:hover {
    background: #0b5ed7;
    border-color: #0b5ed7;
}

/* ── Action buttons ── */
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

#panel-wakapac .wakapac-cell-time    { color: #6c757d; width: 95px; }
#panel-wakapac .wakapac-cell-pac     { color: #0d6efd; }
#panel-wakapac .wakapac-cell-msg     { color: #198754; font-weight: 500; }
#panel-wakapac .wakapac-cell-target  { color: #e67e00; }
#panel-wakapac .wakapac-cell-details { color: #495057; }

#panel-wakapac .wakapac-row-even { background: #fff; }
#panel-wakapac .wakapac-row-odd  { background: #f8f9fa; }

/* Count badge shown on collapsed high-frequency message rows */
#panel-wakapac .wakapac-count-badge {
    display: inline-block;
    margin-left: 5px;
    padding: 0 5px;
    font-size: 10px;
    font-weight: 700;
    line-height: 16px;
    color: #fff;
    background: #6c757d;
    border-radius: 8px;
    vertical-align: middle;
}

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