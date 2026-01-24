// ZTA Audit Dashboard JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Initialize SocketIO connection
    const socket = io();
    
    // Update current time
    function updateTime() {
        const now = new Date();
        document.getElementById('current-time').textContent = 
            now.toLocaleString('en-US', { 
                weekday: 'long',
                year: 'numeric', 
                month: 'long', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
    }
    
    setInterval(updateTime, 1000);
    updateTime();
    
    // SocketIO event handlers
    socket.on('connect', function() {
        console.log('Connected to audit server');
        document.getElementById('connection-status').className = 'badge bg-success';
        document.getElementById('connection-status').textContent = 'Connected';
        
        // Subscribe to all events
        socket.emit('subscribe_events', {});
    });
    
    socket.on('disconnect', function() {
        console.log('Disconnected from audit server');
        document.getElementById('connection-status').className = 'badge bg-danger';
        document.getElementById('connection-status').textContent = 'Disconnected';
    });
    
    socket.on('new_event', function(event) {
        console.log('New event received:', event);
        addEventToView(event);
        updateStatistics();
    });
    
    socket.on('statistics_update', function(stats) {
        updateDashboardStats(stats);
    });
    
    socket.on('active_requests_update', function(data) {
        document.getElementById('active-requests').textContent = data.count;
    });
    
    socket.on('trace_details', function(data) {
        displayTraceFlow(data);
    });
    
    // Initial load
    loadEvents();
    loadUserActivity();
    loadComponentStatus();
    
    // Set up filters
    document.getElementById('event-type-filter').addEventListener('change', loadEvents);
    document.getElementById('component-filter').addEventListener('change', loadEvents);
    document.getElementById('severity-filter').addEventListener('change', loadEvents);
    
    // Trace ID input
    document.getElementById('trace-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const traceId = this.value.trim();
            if (traceId) {
                socket.emit('request_trace', { trace_id: traceId });
            }
        }
    });
});

function loadEvents() {
    const eventType = document.getElementById('event-type-filter').value;
    const component = document.getElementById('component-filter').value;
    const severity = document.getElementById('severity-filter').value;
    
    let url = '/audit/events?limit=50';
    if (eventType) url += `&type=${eventType}`;
    if (component) url += `&component=${component}`;
    if (severity) url += `&severity=${severity}`;
    
    fetch(url)
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('events-container');
            container.innerHTML = '';
            
            document.getElementById('event-count').textContent = data.total;
            
            data.events.forEach(event => {
                container.appendChild(createEventElement(event));
            });
        })
        .catch(error => console.error('Error loading events:', error));
}

function createEventElement(event) {
    const div = document.createElement('div');
    div.className = `event-item ${event.severity}`;
    
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
            <small>Trace: ${event.trace_id.substring(0, 8)}...</small>
        </div>
        ${event.details ? `<div class="mt-2"><small>${JSON.stringify(event.details)}</small></div>` : ''}
    `;
    
    return div;
}

function addEventToView(event) {
    const container = document.getElementById('events-container');
    const eventElement = createEventElement(event);
    
    // Add to top
    if (container.firstChild) {
        container.insertBefore(eventElement, container.firstChild);
    } else {
        container.appendChild(eventElement);
    }
    
    // Limit to 50 events
    while (container.children.length > 50) {
        container.removeChild(container.lastChild);
    }
    
    // Update count
    const count = parseInt(document.getElementById('event-count').textContent) + 1;
    document.getElementById('event-count').textContent = count;
}

function loadUserActivity() {
    fetch('/audit/users/activity?limit=10')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('user-activity');
            container.innerHTML = '';
            
            data.users.forEach(user => {
                container.appendChild(createUserActivityElement(user));
            });
            
            document.getElementById('active-users').textContent = data.total_users;
        })
        .catch(error => console.error('Error loading user activity:', error));
}

function createUserActivityElement(user) {
    const div = document.createElement('div');
    div.className = 'user-activity';
    
    // Get first letter for avatar
    const avatarLetter = user.username ? user.username[0].toUpperCase() : '?';
    
    // Format last activity time
    const lastActive = new Date(user.last_activity);
    const now = new Date();
    const diffMinutes = Math.floor((now - lastActive) / 60000);
    let timeAgo;
    
    if (diffMinutes < 1) timeAgo = 'Just now';
    else if (diffMinutes < 60) timeAgo = `${diffMinutes}m ago`;
    else if (diffMinutes < 1440) timeAgo = `${Math.floor(diffMinutes/60)}h ago`;
    else timeAgo = `${Math.floor(diffMinutes/1440)}d ago`;
    
    div.innerHTML = `
        <div class="user-avatar">${avatarLetter}</div>
        <div style="flex: 1;">
            <div><strong>${user.username}</strong></div>
            <div class="text-muted" style="font-size: 0.8rem;">
                ${user.event_count} events • Last: ${timeAgo}
            </div>
        </div>
        <div>
            ${user.failed_attempts > 0 ? 
                `<span class="badge bg-danger">${user.failed_attempts} fails</span>` : 
                `<span class="badge bg-success">OK</span>`}
        </div>
    `;
    
    return div;
}

function updateDashboardStats(stats) {
    document.getElementById('total-events').textContent = stats.total_events || 0;
    
    // Update alerts count
    const alerts = stats.events_by_type?.SECURITY_ALERT || 0;
    document.getElementById('alerts').textContent = alerts;
    
    // Update component status
    if (stats.server_status) {
        const container = document.getElementById('component-status');
        container.innerHTML = '';
        
        Object.entries(stats.server_status).forEach(([component, status]) => {
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
                        <div class="mt-2">
                            <small>Events: ${stats.events_by_component?.[component] || 0}</small>
                        </div>
                    </div>
                </div>
            `;
            
            container.appendChild(col);
        });
    }
}

function displayTraceFlow(data) {
    const container = document.getElementById('trace-flow');
    
    if (!data.events || data.events.length === 0) {
        container.innerHTML = '<p class="text-muted">No trace found or no events recorded.</p>';
        return;
    }
    
    // Group events by component
    const flowHTML = `
        <div class="trace-flow">
            ${data.events.map((event, index) => `
                <div class="flow-step">
                    <div class="flow-node bg-${getComponentColor(event.source_component)} text-white">
                        <i class="${getComponentIcon(event.source_component)}"></i>
                    </div>
                    <div class="text-center">
                        <small><strong>${event.source_component}</strong></small><br>
                        <small class="text-muted">${event.event_type}</small>
                    </div>
                    ${index < data.events.length - 1 ? '<div class="flow-arrow"><i class="fas fa-arrow-right"></i></div>' : ''}
                </div>
            `).join('')}
        </div>
        <div class="mt-3">
            <h6>Trace Details:</h6>
            <div class="table-responsive">
                <table class="table table-sm">
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
                        ${data.events.map(event => `
                            <tr>
                                <td>${new Date(event.timestamp).toLocaleTimeString()}</td>
                                <td><span class="badge ${getComponentColor(event.source_component)}">${event.source_component}</span></td>
                                <td>${event.event_type}</td>
                                <td>${event.action}</td>
                                <td><span class="badge ${event.status === 'success' ? 'bg-success' : 'bg-danger'}">${event.status}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    
    container.innerHTML = flowHTML;
}

function getComponentColor(component) {
    const colors = {
        'gateway': 'primary',
        'opa_agent': 'success',
        'opa_server': 'warning',
        'api_server': 'info'
    };
    return colors[component] || 'secondary';
}

function getComponentIcon(component) {
    const icons = {
        'gateway': 'fas fa-door-open',
        'opa_agent': 'fas fa-user-shield',
        'opa_server': 'fas fa-gavel',
        'api_server': 'fas fa-database'
    };
    return icons[component] || 'fas fa-server';
}

function loadComponentStatus() {
    fetch('/audit/statistics')
        .then(response => response.json())
        .then(updateDashboardStats)
        .catch(error => console.error('Error loading component status:', error));
}

function refreshEvents() {
    loadEvents();
    loadUserActivity();
    loadComponentStatus();
}

// Auto-refresh every 30 seconds
setInterval(refreshEvents, 30000);