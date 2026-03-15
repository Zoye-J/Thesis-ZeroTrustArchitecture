// ZTA Audit Dashboard — Enhanced JS
// Replaces app/static/js/audit-dashboard.js

// ============================================================
// STATE
// ============================================================
const state = {
    events: [],
    filteredEvents: [],
    filters: { type: 'all', component: 'all', search: '' },
    paused: false,
    maxEvents: 200,
    counts: {},
    socket: null,
    currentView: 'events',
};

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    startClock();
    connectSocket();
    loadEvents();
    loadStats();
    loadComponentStatus();

    document.getElementById('global-search').addEventListener('input', (e) => {
        state.filters.search = e.target.value.toLowerCase();
        renderEvents();
    });

    // Refresh stats every 15s, status every 10s
    setInterval(loadStats, 15000);
    setInterval(loadComponentStatus, 10000);
});

// ============================================================
// CLOCK
// ============================================================
function startClock() {
    const el = document.getElementById('current-time');
    function tick() {
        const now = new Date();
        el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
    }
    tick();
    setInterval(tick, 1000);
}

// ============================================================
// SOCKET
// ============================================================
function connectSocket() {
    try {
        window.socket = io('https://localhost:5002', { secure: true, rejectUnauthorized: false });
        state.socket = window.socket;

        state.socket.on('connect', () => {
            setConnStatus(true);
        });

        state.socket.on('disconnect', () => {
            setConnStatus(false);
        });

        state.socket.on('new_event', (event) => {
            if (!state.paused) {
                ingestEvent(event, true);
            }
        });

        state.socket.on('servers_status', (status) => {
            updateComponentDots(status);
        });

        state.socket.on('trace_details', (data) => {
            renderTraceResult(data);
        });

    } catch (e) {
        setConnStatus(false);
    }
}

function setConnStatus(connected) {
    const el = document.getElementById('conn-status');
    el.className = 'conn-pill ' + (connected ? 'connected' : 'disconnected');
    el.innerHTML = `<div class="live-dot"></div><span>${connected ? 'CONNECTED' : 'OFFLINE'}</span>`;
}

// ============================================================
// EVENT LOADING
// ============================================================
function loadEvents() {
    fetch('/audit/events/recent?limit=100')
        .then(r => r.json())
        .then(data => {
            if (data.success && data.events) {
                state.events = [];
                data.events.forEach(e => ingestEvent(e, false));
                renderEvents();
                updateCounts();
            }
        })
        .catch(err => console.error('Load events failed:', err));
}

function ingestEvent(event, isNew) {
    // Prepend new events
    state.events.unshift(event);
    if (state.events.length > state.maxEvents) {
        state.events = state.events.slice(0, state.maxEvents);
    }

    // Update counts
    const type = event.event_type || 'UNKNOWN';
    state.counts[type] = (state.counts[type] || 0) + 1;
    state.counts['all'] = (state.counts['all'] || 0) + 1;

    // Count denials / errors for stats
    if (type === 'POLICY_DENY') {
        const v = parseInt(document.getElementById('stat-denials').textContent) || 0;
        document.getElementById('stat-denials').textContent = v + 1;
    }
    if (type === 'ERROR') {
        const v = parseInt(document.getElementById('stat-errors').textContent) || 0;
        document.getElementById('stat-errors').textContent = v + 1;
    }

    if (isNew) {
        renderEvents();
        updateCounts();
    }
}

// ============================================================
// RENDER EVENTS
// ============================================================
function renderEvents() {
    const { type, component, search } = state.filters;

    state.filteredEvents = state.events.filter(e => {
        if (type !== 'all' && e.event_type !== type) return false;
        if (component !== 'all' && e.source_component !== component) return false;
        if (search) {
            const haystack = JSON.stringify(e).toLowerCase();
            if (!haystack.includes(search)) return false;
        }
        return true;
    });

    const container = document.getElementById('event-stream');
    const count = state.filteredEvents.length;

    document.getElementById('event-count').textContent = count + ' events';

    if (count === 0) {
        container.innerHTML = '<div class="empty-state"><div style="font-size:24px;opacity:0.3">⋯</div><div>No events match filters</div></div>';
        return;
    }

    // Build rows efficiently
    const rows = state.filteredEvents.map((ev, idx) => buildEventRow(ev, idx)).join('');
    container.innerHTML = rows;

    // Flash first row if it's new
    const first = container.querySelector('.event-row');
    if (first) first.classList.add('new-event');
}

function buildEventRow(ev, idx) {
    const time = ev.timestamp
        ? new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false })
        : '--:--:--';
    const comp = ev.source_component || 'unknown';
    const type = ev.event_type || 'UNKNOWN';
    const action = escapeHtml(ev.action || '');
    const user = ev.username ? `<span style="color:var(--text)">${escapeHtml(ev.username)}</span>` : '<span style="color:var(--text3)">system</span>';
    const traceId = ev.trace_id || '';
    const traceShort = traceId ? traceId.substring(0, 14) + '…' : '—';
    const status = ev.status || 'success';

    const typeClass = getTypeClass(type);

    return `<div class="event-row" onclick="showEventDetail(${idx})" data-idx="${idx}">
        <span class="event-time">${time}</span>
        <span><span class="comp-tag ${comp}">${comp.replace('_',' ')}</span></span>
        <span><span class="type-tag ${typeClass}">${type.replace(/_/g,' ')}</span></span>
        <span class="event-action" title="${escapeHtml(action)}">${escapeHtml(action)}</span>
        <span>
            ${user}<br>
            ${traceId ? `<span class="trace-link" onclick="event.stopPropagation();jumpToTrace('${traceId}')" title="${traceId}">${traceShort}</span>` : ''}
        </span>
        <span style="text-align:center"><div class="status-dot ${status}"></div></span>
    </div>`;
}

function getTypeClass(type) {
    const known = ['POLICY_ALLOW','POLICY_DENY','USER_LOGIN','REQUEST_RECEIVED',
                   'RESPONSE_ENCRYPTED','REQUEST_DECRYPTED','ERROR','JWT_ISSUED'];
    return known.includes(type) ? type : 'default';
}

// ============================================================
// FILTERS
// ============================================================
function setFilter(filterKey, value, el) {
    state.filters[filterKey] = value;

    // Update active chips in same group
    document.querySelectorAll(`[data-filter="${filterKey}"]`).forEach(chip => {
        chip.classList.toggle('active', chip.dataset.value === value);
    });

    renderEvents();
}

function updateCounts() {
    const countEls = document.querySelectorAll('.chip-count[id^="count-"]');
    countEls.forEach(el => {
        const key = el.id.replace('count-', '');
        el.textContent = state.counts[key] || 0;
    });
}

// ============================================================
// STATS
// ============================================================
function loadStats() {
    fetch('/audit/statistics')
        .then(r => r.json())
        .then(data => {
            document.getElementById('stat-total').textContent = data.total_events || 0;
            document.getElementById('stat-users').textContent = data.active_users || 0;
            if (data.server_status) updateComponentDots(data.server_status);
        })
        .catch(() => {});
}

// ============================================================
// COMPONENT STATUS
// ============================================================
function loadComponentStatus() {
    fetch('/audit/statistics')
        .then(r => r.json())
        .then(data => {
            if (data.server_status) updateComponentDots(data.server_status);
        })
        .catch(() => {});
}

function updateComponentDots(status) {
    Object.entries(status).forEach(([name, state_]) => {
        const dot = document.getElementById('dot-' + name);
        if (dot) {
            dot.className = 'comp-dot ' + (state_ === 'running' ? 'running' : 'down');
        }
    });
}

// ============================================================
// VIEW SWITCHING
// ============================================================
function switchView(view, btn) {
    state.currentView = view;

    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    if (btn) btn.classList.add('active');

    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById('view-' + view);
    if (panel) panel.classList.add('active');

    if (view === 'alerts') loadAlerts();
}

// ============================================================
// PAUSE / CLEAR
// ============================================================
function togglePause() {
    state.paused = !state.paused;
    const btn = document.getElementById('pause-btn');
    btn.textContent = state.paused ? '▶' : '⏸';
    btn.title = state.paused ? 'Resume' : 'Pause';
    showToast(state.paused ? 'Stream paused' : 'Stream resumed', 'info');
}

function clearEvents() {
    state.events = [];
    state.filteredEvents = [];
    state.counts = {};
    renderEvents();
    updateCounts();
    showToast('Events cleared', 'info');
}

// ============================================================
// EVENT DETAIL DRAWER
// ============================================================
function showEventDetail(idx) {
    const ev = state.filteredEvents[idx];
    if (!ev) return;

    const body = document.getElementById('drawer-body');
    const time = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'Unknown';

    body.innerHTML = `
        <div class="drawer-field">
            <div class="drawer-field-label">Event ID</div>
            <div class="drawer-field-value" style="color:var(--text3);font-size:10px">${escapeHtml(ev.event_id || '—')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Event Type</div>
            <div class="drawer-field-value"><span class="type-tag ${getTypeClass(ev.event_type)}">${escapeHtml(ev.event_type || '—')}</span></div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Timestamp</div>
            <div class="drawer-field-value">${escapeHtml(time)}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Component</div>
            <div class="drawer-field-value"><span class="comp-tag ${escapeHtml(ev.source_component || '')}">${escapeHtml(ev.source_component || '—')}</span></div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Action</div>
            <div class="drawer-field-value">${escapeHtml(ev.action || '—')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Status</div>
            <div class="drawer-field-value">
                <div class="status-dot ${escapeHtml(ev.status || 'success')}" style="display:inline-block;margin-right:6px;vertical-align:middle"></div>
                ${escapeHtml(ev.status || '—')}
            </div>
        </div>
        <hr class="drawer-divider">
        <div class="drawer-field">
            <div class="drawer-field-label">User</div>
            <div class="drawer-field-value">${escapeHtml(ev.username || ev.user_id || '(system)')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Source IP</div>
            <div class="drawer-field-value">${escapeHtml(ev.source_ip || '—')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Trace ID</div>
            <div class="drawer-field-value" style="font-size:10px">
                ${ev.trace_id ? `${escapeHtml(ev.trace_id)} <span class="trace-link" onclick="jumpToTrace('${ev.trace_id}')" style="margin-left:6px">[view trace →]</span>` : '—'}
            </div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Request ID</div>
            <div class="drawer-field-value" style="font-size:10px;color:var(--text3)">${escapeHtml(ev.request_id || '—')}</div>
        </div>
        ${ev.processing_time_ms != null ? `
        <div class="drawer-field">
            <div class="drawer-field-label">Processing Time</div>
            <div class="drawer-field-value">${ev.processing_time_ms}ms</div>
        </div>` : ''}
        <hr class="drawer-divider">
        <div class="drawer-field">
            <div class="drawer-field-label">Details</div>
            <pre class="json-pre">${escapeHtml(JSON.stringify(ev.details || {}, null, 2))}</pre>
        </div>
    `;

    document.getElementById('detail-drawer').classList.add('open');
}

function closeDrawer() {
    document.getElementById('detail-drawer').classList.remove('open');
}

// ============================================================
// TRACE SEARCH
// ============================================================
function searchTraceById() {
    const input = document.getElementById('trace-input');
    const traceId = input.value.trim();
    if (!traceId) { showToast('Enter a trace ID', 'error'); return; }
    searchTrace(traceId);
}

function jumpToTrace(traceId) {
    document.getElementById('trace-input').value = traceId;
    switchView('trace', document.querySelectorAll('.nav-tab')[1]);
    searchTrace(traceId);
}

function searchTrace(traceId) {
    const body = document.getElementById('trace-body');
    body.innerHTML = `
        <div class="trace-empty">
            <div class="trace-empty-icon" style="animation:spin 1s linear infinite;display:inline-block">◌</div>
            <div class="trace-empty-text">Searching for <code style="color:var(--accent)">${escapeHtml(traceId)}</code></div>
        </div>`;

    if (state.socket && state.socket.connected) {
        state.socket.emit('request_trace', { trace_id: traceId });
    } else {
        fetch(`/audit/trace/${encodeURIComponent(traceId)}`)
            .then(r => r.json())
            .then(data => renderTraceResult(data))
            .catch(err => {
                document.getElementById('trace-body').innerHTML =
                    `<div class="trace-empty"><div class="trace-empty-text" style="color:var(--red)">Error: ${escapeHtml(err.message)}</div></div>`;
            });
    }
}

function loadRecentTraces() {
    const recent = [...new Set(state.events.slice(0,50).map(e => e.trace_id).filter(Boolean))].slice(0,6);
    if (!recent.length) { showToast('No recent traces in stream', 'info'); return; }

    const body = document.getElementById('trace-body');
    body.innerHTML = `
        <div class="drawer-field-label" style="padding:8px 0 12px">Recent trace IDs — click to search</div>
        ${recent.map(t => `
            <div style="padding:8px 12px;margin-bottom:6px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;cursor:pointer;font-size:11px;color:var(--accent2);transition:background 0.15s"
                 onmouseover="this.style.background='var(--bg4)'"
                 onmouseout="this.style.background='var(--bg3)'"
                 onclick="document.getElementById('trace-input').value='${t}';searchTrace('${t}')">
                ${t}
            </div>
        `).join('')}
    `;
}

function renderTraceResult(data) {
    const body = document.getElementById('trace-body');

    if (!data.events || data.events.length === 0) {
        body.innerHTML = `
            <div class="trace-empty">
                <div class="trace-empty-icon">⊘</div>
                <div class="trace-empty-text">
                    No events found for trace:<br>
                    <code style="color:var(--text2);font-size:10px">${escapeHtml(data.trace_id || '?')}</code>
                </div>
            </div>`;
        return;
    }

    const events = [...data.events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const components = [...new Set(events.map(e => e.source_component))];

    // Duration
    const timestamps = events.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t));
    const duration = timestamps.length >= 2
        ? ((Math.max(...timestamps) - Math.min(...timestamps)) + 'ms')
        : 'N/A';

    const allSuccess = events.every(e => e.status === 'success');
    const user = events.find(e => e.username)?.username || 'System';

    // Component colors for trace nodes
    const compColors = {
        gateway: 'var(--accent2)', opa_agent: 'var(--green)',
        opa_server: 'var(--amber)', api_server: 'var(--purple)',
        auth_server: 'var(--red)', service_communicator: 'var(--text2)'
    };

    body.innerHTML = `
        <!-- Flow viz -->
        <div class="trace-flow-viz">
            ${components.map((comp, i) => `
                <div class="trace-node">
                    <div class="trace-node-icon" style="background:rgba(${hexToRgb(compColors[comp]||'200,216,232')},0.1);border-color:rgba(${hexToRgb(compColors[comp]||'200,216,232')},0.3)">
                        ${getCompEmoji(comp)}
                    </div>
                    <div class="trace-node-label">${comp.replace('_',' ')}</div>
                    <div class="trace-node-count">${events.filter(e=>e.source_component===comp).length} ev</div>
                </div>
                ${i < components.length-1 ? '<div class="trace-arrow"></div>' : ''}
            `).join('')}
        </div>

        <!-- Summary grid -->
        <div class="trace-summary-grid" style="margin-bottom:16px">
            <div class="trace-summary-item">
                <div class="ts-label">Trace ID</div>
                <div class="ts-value" style="font-size:9px;color:var(--text3);word-break:break-all">${escapeHtml(data.trace_id)}</div>
            </div>
            <div class="trace-summary-item">
                <div class="ts-label">Duration</div>
                <div class="ts-value">${duration}</div>
            </div>
            <div class="trace-summary-item">
                <div class="ts-label">User</div>
                <div class="ts-value">${escapeHtml(user)}</div>
            </div>
            <div class="trace-summary-item">
                <div class="ts-label">Result</div>
                <div class="ts-value" style="color:${allSuccess?'var(--green)':'var(--amber)'}">
                    ${allSuccess ? '✓ Success' : '⚠ Has issues'}
                </div>
            </div>
        </div>

        <!-- Events table -->
        <table class="trace-events-table" style="width:100%;border-collapse:collapse">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Component</th>
                    <th>Event</th>
                    <th>Action</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                ${events.map(ev => `
                    <tr>
                        <td>${ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString('en-US',{hour12:false}) : '—'}</td>
                        <td><span class="comp-tag ${escapeHtml(ev.source_component||'')}">${escapeHtml(ev.source_component||'—')}</span></td>
                        <td><span class="type-tag ${getTypeClass(ev.event_type)}" style="font-size:9px">${escapeHtml(ev.event_type||'—')}</span></td>
                        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(ev.action||'')}">${escapeHtml(ev.action||'—')}</td>
                        <td><div class="status-dot ${ev.status||'success'}" style="margin:0 auto"></div></td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// ============================================================
// ALERTS
// ============================================================
function loadAlerts() {
    fetch('/audit/alerts')
        .then(r => r.json())
        .then(data => {
            const list = document.getElementById('alerts-list');
            const alerts = data.alerts || [];
            document.getElementById('alert-count').textContent = alerts.length + ' alerts';

            if (!alerts.length) {
                list.innerHTML = '<div class="empty-state">No alerts detected</div>';
                return;
            }

            list.innerHTML = alerts.map(ev => `
                <div class="alert-item" onclick='showAlertDetail(${escapeHtml(JSON.stringify(ev))})'>
                    <div class="alert-sev ${escapeHtml(ev.severity||'INFO')}"></div>
                    <div class="alert-content">
                        <div class="alert-type">${escapeHtml(ev.event_type||'Alert')}</div>
                        <div class="alert-meta">
                            ${escapeHtml(ev.username || 'system')} &nbsp;·&nbsp;
                            ${escapeHtml(ev.source_component||'unknown')} &nbsp;·&nbsp;
                            ${ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '—'}
                        </div>
                        <div style="font-size:11px;color:var(--text2);margin-top:3px">${escapeHtml(ev.action||'')}</div>
                    </div>
                    <div style="font-size:9px;padding:2px 6px;border-radius:3px;border:1px solid rgba(255,61,90,0.3);color:var(--red);align-self:flex-start">${escapeHtml(ev.severity||'INFO')}</div>
                </div>
            `).join('');
        })
        .catch(() => {});
}

function showAlertDetail(ev) {
    // Reuse drawer
    const body = document.getElementById('drawer-body');
    body.innerHTML = `
        <div class="drawer-field">
            <div class="drawer-field-label">Severity</div>
            <div class="drawer-field-value" style="color:var(--red)">${escapeHtml(ev.severity||'—')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Event Type</div>
            <div class="drawer-field-value">${escapeHtml(ev.event_type||'—')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Action</div>
            <div class="drawer-field-value">${escapeHtml(ev.action||'—')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">User</div>
            <div class="drawer-field-value">${escapeHtml(ev.username||'system')}</div>
        </div>
        <div class="drawer-field">
            <div class="drawer-field-label">Timestamp</div>
            <div class="drawer-field-value">${escapeHtml(ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—')}</div>
        </div>
        <hr class="drawer-divider">
        <div class="drawer-field">
            <div class="drawer-field-label">Details</div>
            <pre class="json-pre">${escapeHtml(JSON.stringify(ev.details || {}, null, 2))}</pre>
        </div>
    `;
    document.getElementById('detail-drawer').classList.add('open');
}

// ============================================================
// HELPERS
// ============================================================
function escapeHtml(text) {
    if (typeof text !== 'string') text = String(text ?? '');
    return text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function getCompEmoji(comp) {
    const m = { gateway:'⬡', opa_agent:'⬢', opa_server:'⬡', api_server:'⬡', auth_server:'⬡', service_communicator:'⬡' };
    return m[comp] || '⬡';
}

function hexToRgb(color) {
    // Returns "r,g,b" for css var fallback
    if (color.startsWith('var(')) return '200,216,232';
    const hex = color.replace('#','');
    if (hex.length !== 6) return '200,216,232';
    const r = parseInt(hex.slice(0,2),16);
    const g = parseInt(hex.slice(2,4),16);
    const b = parseInt(hex.slice(4,6),16);
    return `${r},${g},${b}`;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast-item ${type}`;
    const icons = { success:'✓', error:'✕', info:'ℹ' };
    toast.innerHTML = `<span style="color:var(--${type==='success'?'green':type==='error'?'red':'accent'})">${icons[type]||'·'}</span> ${escapeHtml(message)}`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

// Globals for HTML onclick compatibility
window.searchTraceById = searchTraceById;
window.searchTrace = searchTrace;
window.switchView = switchView;
window.setFilter = setFilter;
window.loadEvents = loadEvents;
window.clearEvents = clearEvents;
window.togglePause = togglePause;
window.closeDrawer = closeDrawer;
window.showEventDetail = showEventDetail;
window.loadRecentTraces = loadRecentTraces;
window.loadAlerts = loadAlerts;
window.jumpToTrace = jumpToTrace;
window.showAlertDetail = showAlertDetail;
window.refreshEvents = () => { loadEvents(); loadStats(); showToast('Refreshed', 'success'); };