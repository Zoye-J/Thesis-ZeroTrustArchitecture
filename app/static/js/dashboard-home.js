// Dashboard home page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    const socket = io();
    
    // Update time
    function updateTime() {
        document.getElementById('current-time').textContent = 
            new Date().toLocaleString();
    }
    setInterval(updateTime, 1000);
    updateTime();
    
    // Socket event handlers
    socket.on('connect', function() {
        console.log('Connected to dashboard server');
        document.getElementById('connection-status').className = 'badge bg-success';
        document.getElementById('connection-status').textContent = 'Connected';
    });
    
    socket.on('disconnect', function() {
        document.getElementById('connection-status').className = 'badge bg-danger';
        document.getElementById('connection-status').textContent = 'Disconnected';
    });
    
    socket.on('new_event', function(event) {
        addRecentEvent(event);
    });
    
    socket.on('statistics_update', function(stats) {
        updateStats(stats);
    });
    
    socket.on('servers_status', function(status) {
        updateServerStatus(status);
    });
    
    socket.on('active_requests_update', function(data) {
        document.getElementById('active-requests').textContent = data.count;
    });
    
    // Load initial data
    loadRecentEvents();
    loadStats();
    
    // Auto-refresh every 30 seconds
    setInterval(loadRecentEvents, 30000);
    setInterval(loadStats, 30000);
});

function loadRecentEvents() {
    fetch('/audit/events?limit=10')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('recent-events');
            container.innerHTML = '';
            
            data.events.forEach(event => {
                container.appendChild(createEventCard(event));
            });
        })
        .catch(error => console.error('Error loading events:', error));
}

function createEventCard(event) {
    const div = document.createElement('div');
    div.className = 'card mb-2';
    
    const severityClass = {
        'CRITICAL': 'border-danger',
        'HIGH': 'border-warning',
        'MEDIUM': 'border-info',
        'LOW': 'border-primary',
        'INFO': 'border-secondary'
    }[event.severity] || 'border-secondary';
    
    div.className += ` ${severityClass}`;
    
    const time = new Date(event.timestamp).toLocaleTimeString();
    
    div.innerHTML = `
        <div class="card-body py-2">
            <div class="d-flex justify-content-between">
                <div>
                    <strong>${event.event_type}</strong>
                    <br>
                    <small class="text-muted">${event.action}</small>
                </div>
                <div class="text-end">
                    <small>${time}</small><br>
                    <span class="badge bg-${event.status === 'success' ? 'success' : 'danger'}">
                        ${event.status}
                    </span>
                </div>
            </div>
            ${event.username ? `<small><i class="fas fa-user"></i> ${event.username}</small>` : ''}
        </div>
    `;
    
    return div;
}

function addRecentEvent(event) {
    const container = document.getElementById('recent-events');
    const eventCard = createEventCard(event);
    
    container.insertBefore(eventCard, container.firstChild);
    
    // Keep only last 10 events
    while (container.children.length > 10) {
        container.removeChild(container.lastChild);
    }
}

function updateStats(stats) {
    document.getElementById('total-events').textContent = stats.total_events || 0;
    
    // Update user count from stats
    if (stats.top_users) {
        document.getElementById('active-users').textContent = Object.keys(stats.top_users).length;
    }
}

function loadStats() {
    fetch('/audit/statistics')
        .then(response => response.json())
        .then(updateStats)
        .catch(error => console.error('Error loading stats:', error));
}

function updateServerStatus(status) {
    const container = document.getElementById('server-status');
    container.innerHTML = '';
    
    const servers = [
        { name: 'gateway', port: 5000, secure: true },
        { name: 'api_server', port: 5001, secure: false },
        { name: 'opa_agent', port: 8282, secure: false },
        { name: 'opa_server', port: 8181, secure: true }
    ];
    
    servers.forEach(server => {
        const statusText = status[server.name] || 'unknown';
        const isRunning = statusText === 'running';
        
        const col = document.createElement('div');
        col.className = 'col-md-3 mb-3';
        
        col.innerHTML = `
            <div class="card server-card ${isRunning ? 'server-running' : 'server-down'}">
                <div class="card-body text-center">
                    <i class="fas fa-server fa-3x mb-3 ${isRunning ? 'text-success' : 'text-danger'}"></i>
                    <h5>${server.name.replace('_', ' ').toUpperCase()}</h5>
                    <p class="text-muted">Port: ${server.port}</p>
                    <span class="badge ${isRunning ? 'bg-success' : 'bg-danger'}">
                        ${statusText.toUpperCase()}
                    </span>
                    <div class="mt-2">
                        <small>${server.secure ? 'HTTPS' : 'HTTP'}</small>
                    </div>
                </div>
            </div>
        `;
        
        container.appendChild(col);
    });
}