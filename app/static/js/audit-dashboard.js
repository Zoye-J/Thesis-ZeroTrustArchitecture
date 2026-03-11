// ZTA Audit Dashboard JavaScript - SIMPLIFIED WITH TRACE SEARCH

// ========== GLOBAL FUNCTIONS (accessible from HTML onclick) ==========

// Helper function for button click - MUST BE GLOBAL
function searchTraceById() {
    const traceId = document.getElementById('trace-input').value.trim();
    if (traceId) {
        searchTrace(traceId);
    } else {
        showNotification('Please enter a trace ID', 'warning');
    }
}

// Notification function
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Main trace search function - MUST BE GLOBAL
function searchTrace(traceId) {
    console.log(`Searching trace: ${traceId}`);
    
    // Show loading
    const traceFlowDiv = document.getElementById('trace-flow');
    traceFlowDiv.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary"></div>
            <p class="mt-2">Searching for trace: <code>${traceId}</code></p>
        </div>
    `;
    
    // Try WebSocket first if connected
    if (window.socket && window.socket.connected) {
        console.log('Using WebSocket for trace search');
        window.socket.emit('request_trace', { trace_id: traceId });
    } else {
        // Fallback to REST API
        console.log('Using REST API for trace search');
        fetch(`/audit/trace/${encodeURIComponent(traceId)}`)  // Added encodeURIComponent
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                displayTraceFlow(data);
            })
            .catch(error => {
                console.error('Trace search error:', error);
                const traceFlowDiv = document.getElementById('trace-flow');
                traceFlowDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <h5>Error searching for trace</h5>
                        <p>Trace ID: <code>${traceId}</code></p>
                        <p>Error: ${error.message}</p>
                        <small class="text-muted">Try a different trace ID or check server connection.</small>
                    </div>
                `;
            });
    }
}

// ========== DOM CONTENT LOADED ==========

document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard loaded');
    
    // Store socket globally for trace search
    window.socket = io('https://localhost:5002');
    const socket = window.socket;
    
    // Update current time
    function updateTime() {
        const now = new Date();
        document.getElementById('current-time').textContent = 
            now.toLocaleString('en-US', { 
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
    }
    
    setInterval(updateTime, 1000);
    updateTime();
    
    // SocketIO connection status
    socket.on('connect', function() {
        console.log('✓ Connected to dashboard');
        document.getElementById('connection-status').className = 'badge bg-success';
        document.getElementById('connection-status').textContent = 'Connected';
    });
    
    socket.on('disconnect', function() {
        console.log('✗ Disconnected from dashboard');
        document.getElementById('connection-status').className = 'badge bg-danger';
        document.getElementById('connection-status').textContent = 'Disconnected';
    });
    
    socket.on('new_event', function(event) {
        console.log('New event:', event.event_type);
        addEventToView(event);
    });
    
    socket.on('servers_status', function(status) {
        updateComponentStatus(status);
    });
    
    // Handle trace search results from WebSocket
    socket.on('trace_details', function(data) {
        console.log('Trace details received:', data);
        displayTraceFlow(data);
    });
    
    // Initial load
    loadEvents();
    loadComponentStatus();
    
    // Set up filters
    document.getElementById('event-type-filter').addEventListener('change', loadEvents);
    document.getElementById('component-filter').addEventListener('change', loadEvents);
    
    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', function() {
        loadEvents();
        loadComponentStatus();
        showNotification('Dashboard refreshed!', 'info');
    });
    
    // Trace ID search - Enter key
    document.getElementById('trace-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const traceId = this.value.trim();
            if (traceId) {
                console.log(`Searching for trace (Enter): ${traceId}`);
                searchTrace(traceId);  // Call the global function
            }
        }
    });
    
    // Auto-refresh every 30 seconds
    setInterval(function() {
        loadComponentStatus();
    }, 30000);
});

// ========== OTHER GLOBAL FUNCTIONS ==========

// Display trace flow results
function displayTraceFlow(data) {
    const container = document.getElementById('trace-flow');
    
    // Handle WebSocket response format
    if (data.events === undefined && data.trace_id) {
        // This is from WebSocket
        data = {
            trace_id: data.trace_id,
            events: data.events || [],
            found: data.found || false,
            message: data.message || '',
            count: data.count || 0
        };
    }
    
    if (!data.events || data.events.length === 0) {
        container.innerHTML = `
            <div class="alert alert-warning">
                <h5>Trace: ${data.trace_id || 'Unknown'}</h5>
                <p>${data.message || 'No events found for this trace ID.'}</p>
                <small class="text-muted">Try copying a trace ID from the events above.</small>
                <div class="mt-2">
                    <button class="btn btn-sm btn-primary" onclick="copyTraceId('${data.trace_id || ''}')">
                        <i class="fas fa-copy"></i> Copy Trace ID
                    </button>
                </div>
            </div>
        `;
        return;
    }
    
    console.log(`Found ${data.events.length} events for trace: ${data.trace_id}`);
    
    // Create the flow visualization
    const flowHTML = createTraceFlowHTML(data);
    container.innerHTML = flowHTML;
}

// Helper function to create trace flow HTML
function createTraceFlowHTML(data) {
    const events = data.events;
    
    // Sort events by timestamp
    events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    
    // Group by component for visualization
    const components = [...new Set(events.map(e => e.source_component))];
    
    return `
        <div class="card">
            <div class="card-header bg-info text-white">
                <i class="fas fa-project-diagram"></i> Trace Flow Analysis
                <span class="badge bg-light text-dark float-end">${events.length} events</span>
            </div>
            <div class="card-body">
                <!-- Trace ID Header -->
                <div class="mb-3 p-3 bg-light rounded">
                    <h5>Trace ID: <code>${data.trace_id}</code></h5>
                    <button class="btn btn-sm btn-outline-primary" onclick="copyTraceId('${data.trace_id}')">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                </div>
                
                <!-- Component Flow Visualization -->
                <h6>Request Flow:</h6>
                <div class="trace-flow mb-4">
                    ${components.map((component, index) => `
                        <div class="flow-step">
                            <div class="flow-node bg-${getComponentColor(component)} text-white">
                                <i class="${getComponentIcon(component)}"></i>
                            </div>
                            <div class="text-center">
                                <small><strong>${component.toUpperCase()}</strong></small>
                                <br>
                                <small class="text-muted">
                                    ${events.filter(e => e.source_component === component).length} events
                                </small>
                            </div>
                            ${index < components.length - 1 ? '<div class="flow-arrow"><i class="fas fa-arrow-right"></i></div>' : ''}
                        </div>
                    `).join('')}
                </div>
                
                <!-- Events Table -->
                <h6>Event Timeline:</h6>
                <div class="table-responsive">
                    <table class="table table-sm table-hover">
                        <thead class="table-light">
                            <tr>
                                <th>Time</th>
                                <th>Component</th>
                                <th>Event Type</th>
                                <th>Action</th>
                                <th>User</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${events.map(event => `
                                <tr>
                                    <td><small>${new Date(event.timestamp).toLocaleTimeString()}</small></td>
                                    <td><span class="badge ${getComponentColor(event.source_component)}">${event.source_component}</span></td>
                                    <td><code>${event.event_type}</code></td>
                                    <td>${event.action}</td>
                                    <td>${event.username || 'System'}</td>
                                    <td><span class="badge ${event.status === 'success' ? 'bg-success' : 'bg-danger'}">${event.status}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                
                <!-- Summary -->
                <div class="mt-3 p-3 bg-light rounded">
                    <h6>Trace Summary:</h6>
                    <div class="row">
                        <div class="col-md-3 mb-2">
                            <strong>Trace ID:</strong><br>
                            <code class="small">${data.trace_id}</code>
                        </div>
                        <div class="col-md-2 mb-2">
                            <strong>Total Events:</strong><br>
                            <span class="badge bg-primary">${events.length}</span>
                        </div>
                        <div class="col-md-3 mb-2">
                            <strong>Components Involved:</strong><br>
                            ${components.map(c => `<span class="badge ${getComponentColor(c)}">${c}</span>`).join(' ')}
                        </div>
                        <div class="col-md-2 mb-2">
                            <strong>Duration:</strong><br>
                            ${calculateTraceDuration(events)}
                        </div>
                        <div class="col-md-2 mb-2">
                            <strong>Status:</strong><br>
                            <span class="badge ${events.every(e => e.status === 'success') ? 'bg-success' : 'bg-warning'}">
                                ${events.every(e => e.status === 'success') ? 'All Success' : 'Has Issues'}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Helper function to calculate trace duration
function calculateTraceDuration(events) {
    if (events.length < 2) return 'N/A';
    
    const timestamps = events.map(e => new Date(e.timestamp).getTime());
    const start = Math.min(...timestamps);
    const end = Math.max(...timestamps);
    const duration = end - start;
    
    if (duration < 1000) return `${duration}ms`;
    return `${(duration / 1000).toFixed(2)}s`;
}

// Helper function to get component color
function getComponentColor(component) {
    const colors = {
        'gateway': 'primary',
        'opa_agent': 'success',
        'opa_server': 'warning',
        'api_server': 'info',
        'auth_server': 'secondary',
        'service_communicator': 'dark'
    };
    return colors[component] || 'secondary';
}

// Helper function to get component icon
function getComponentIcon(component) {
    const icons = {
        'gateway': 'fas fa-door-open',
        'opa_agent': 'fas fa-user-shield',
        'opa_server': 'fas fa-gavel',
        'api_server': 'fas fa-database',
        'auth_server': 'fas fa-key',
        'service_communicator': 'fas fa-exchange-alt'
    };
    return icons[component] || 'fas fa-server';
}

// Copy trace ID to clipboard
function copyTraceId(traceId) {
    navigator.clipboard.writeText(traceId).then(() => {
        showNotification(`Copied: ${traceId}`, 'success');
    }).catch(err => {
        console.error('Copy failed:', err);
        showNotification('Copy failed', 'danger');
    });
}

// Load events from server
function loadEvents() {
    const eventType = document.getElementById('event-type-filter').value;
    const component = document.getElementById('component-filter').value;
    
    let url = '/audit/events?limit=50';
    if (eventType) url += `&type=${eventType}`;
    if (component) url += `&component=${component}`;
    
    fetch(url)
        .then(response => response.json())
        .then(data => {
            console.log(`Loaded ${data.total} events`);
            displayEvents(data.events);
        })
        .catch(error => console.error('Error loading events:', error));
}

// Display events in the container
function displayEvents(events) {
    const container = document.getElementById('events-container');
    container.innerHTML = '';
    
    document.getElementById('event-count').textContent = events.length;
    
    events.forEach(event => {
        container.appendChild(createEventElement(event));
    });
}

// Create event HTML element
function createEventElement(event) {
    const div = document.createElement('div');
    div.className = `event-item ${event.severity || 'INFO'}`;
    
    // Format timestamp
    const timestamp = new Date(event.timestamp).toLocaleTimeString();
    
    // Component badge
    const componentBadge = `<span class="component-badge ${event.source_component}">
        ${event.source_component.toUpperCase()}
    </span>`;
    
    // User info
    const userInfo = event.username ? 
        `<span class="event-user">${event.username}</span>` : 
        '<span class="text-muted">System</span>';
    
    // Make trace ID clickable for search
    const traceId = event.trace_id || 'N/A';
    const traceShort = traceId.substring(0, 8);
    const traceLink = traceId !== 'N/A' ? 
        `<a href="javascript:void(0);" onclick="searchTrace('${traceId}')" title="Search this trace" class="text-primary">
            ${traceShort}...
        </a>` : 
        `<span class="text-muted">N/A</span>`;
    
    div.innerHTML = `
        <div class="d-flex justify-content-between">
            <div>
                ${componentBadge}
                <strong>${event.event_type}</strong>
            </div>
            <div class="event-time">${timestamp}</div>
        </div>
        <div class="event-action mt-1">${event.action}</div>
        <div class="mt-2">
            ${userInfo}
            <span class="text-muted">•</span>
            <small>Trace: ${traceLink}</small>
        </div>
        ${event.details ? `<div class="mt-2"><small><pre class="bg-light p-2 rounded">${JSON.stringify(event.details, null, 2)}</pre></small></div>` : ''}
    `;
    
    return div;
}

// Add new event to view (for real-time)
function addEventToView(event) {
    const container = document.getElementById('events-container');
    const eventElement = createEventElement(event);
    
    // Add to top
    container.insertBefore(eventElement, container.firstChild);
    
    // Limit to 50 events
    while (container.children.length > 50) {
        container.removeChild(container.lastChild);
    }
    
    // Update count
    const count = parseInt(document.getElementById('event-count').textContent) + 1;
    document.getElementById('event-count').textContent = count;
}

// Load and update component status
function loadComponentStatus() {
    fetch('/audit/statistics')
        .then(response => response.json())
        .then(data => {
            console.log('Statistics:', data);
            updateStatistics(data);
            updateComponentCards(data.server_status);
        })
        .catch(error => console.error('Error loading statistics:', error));
}

// Update statistics at the top
function updateStatistics(stats) {
    document.getElementById('total-events').textContent = stats.total_events || 0;
    document.getElementById('active-users').textContent = stats.active_users || 0;
    document.getElementById('active-requests').textContent = stats.active_requests || 0;
    document.getElementById('alerts').textContent = stats.security_alerts || 0;
}

// Update component status cards
function updateComponentCards(serverStatus) {
    const container = document.getElementById('component-status');
    container.innerHTML = '';
    
    if (!serverStatus) return;
    
    Object.entries(serverStatus).forEach(([component, status]) => {
        const col = document.createElement('div');
        col.className = 'col-md-3 mb-3';
        
        const statusClass = status === 'running' ? 'success' : 'danger';
        const icon = status === 'running' ? 'fa-check-circle' : 'fa-times-circle';
        
        col.innerHTML = `
            <div class="card">
                <div class="card-body text-center">
                    <i class="fas ${icon} fa-2x text-${statusClass}"></i>
                    <h5 class="mt-2">${component.replace('_', ' ').toUpperCase()}</h5>
                    <span class="badge bg-${statusClass}">${status.toUpperCase()}</span>
                </div>
            </div>
        `;
        
        container.appendChild(col);
    });
}

// For compatibility with existing code
function refreshEvents() {
    loadEvents();
    loadComponentStatus();
}