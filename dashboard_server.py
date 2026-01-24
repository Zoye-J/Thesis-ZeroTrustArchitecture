# dashboard_server.py - SIMPLIFIED VERSION
"""
ZTA Real-Time Dashboard Server
Separate server for WebSocket-based monitoring dashboard
Runs on port 5002
NO EVENTLET NEEDED!
"""

import sys
import os
import time
import threading
import requests
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# Create Flask app WITHOUT eventlet
app = Flask(__name__, template_folder="app/templates", static_folder="app/static")

# Initialize SocketIO WITHOUT eventlet
socketio = SocketIO(
    app, cors_allowed_origins="*", async_mode="threading"
)  # Use threading instead of eventlet

# Configure app
app.config["SECRET_KEY"] = "dashboard-secret-key-2024"
app.config["SESSION_COOKIE_SECURE"] = False  # HTTP for dashboard (internal)
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Import and initialize dashboard routes
try:
    from app.audit.routes import (
        audit_bp,
        init_socketio,
        init_socketio_handlers,
        start_background_updates,
    )

    # Register blueprint
    app.register_blueprint(audit_bp)

    # Initialize SocketIO
    init_socketio(socketio)
    init_socketio_handlers(socketio)
    start_background_updates(socketio)

    print("✅ Audit routes loaded successfully")
except ImportError as e:
    print(f"⚠️ Could not load audit routes: {e}")
    # Create a simple audit blueprint
    audit_bp = None

# ========== DASHBOARD-ONLY ROUTES ==========


@app.route("/")
def dashboard_home():
    """Main dashboard landing page"""
    return render_template("audit_dashboard.html")


@app.route("/live")
def live_dashboard():
    """Live events dashboard"""
    return render_template("audit.html")


@app.route("/status")
def server_status():
    """Dashboard health endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "server": "dashboard",
            "port": 5002,
            "websocket": "active",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


@app.route("/test")
def test_page():
    """Simple test page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZTA Dashboard Test</title>
        <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    </head>
    <body>
        <h1>ZTA Dashboard Test</h1>
        <p>WebSocket Status: <span id="status">Not Connected</span></p>
        <script>
            const socket = io();
            socket.on('connect', () => {
                document.getElementById('status').textContent = 'Connected';
                document.getElementById('status').style.color = 'green';
            });
            socket.on('disconnect', () => {
                document.getElementById('status').textContent = 'Disconnected';
                document.getElementById('status').style.color = 'red';
            });
        </script>
    </body>
    </html>
    """


# ========== BACKGROUND TASKS ==========

server_status_cache = {
    "gateway": "unknown",
    "api_server": "unknown",
    "opa_agent": "unknown",
    "opa_server": "unknown",
}


def check_servers_status():
    """Periodically check status of all ZTA servers"""
    servers = {
        "gateway": "https://localhost:5000/health",
        "api_server": "http://localhost:5001/health",
        "opa_agent": "http://localhost:8282/health",
        "opa_server": "https://localhost:8181/health",
    }

    while True:
        try:
            status = {}
            for name, url in servers.items():
                try:
                    # Disable SSL verification for self-signed certs
                    response = requests.get(url, timeout=2, verify=False)
                    status[name] = "running" if response.status_code == 200 else "down"
                except Exception as e:
                    status[name] = "down"

            # Update cache
            global server_status_cache
            server_status_cache = status

            # Emit status update to all connected clients
            socketio.emit("servers_status", status)

        except Exception as e:
            print(f"Error checking server status: {e}")

        time.sleep(10)  # Check every 10 seconds


@app.route("/api/servers/status")
def get_servers_status():
    """API endpoint to get server status"""
    return jsonify(server_status_cache)


# ========== MAIN EXECUTION ==========

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 ZTA REAL-TIME DASHBOARD SERVER")
    print("=" * 60)
    print(f"📊 Port: 5002")
    print(f"🔗 URL: http://localhost:5002")
    print(f"📈 Live Events: http://localhost:5002/live")
    print(f"🔌 WebSocket: Enabled (threading mode)")
    print("=" * 60)
    print("Monitoring servers on:")
    print("• Gateway: https://localhost:5000")
    print("• API Server: http://localhost:5001")
    print("• OPA Agent: http://localhost:8282")
    print("• OPA Server: https://localhost:8181")
    print("=" * 60)

    # Disable SSL warnings for self-signed certs
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Start server status monitoring in background
    status_thread = threading.Thread(target=check_servers_status, daemon=True)
    status_thread.start()

    # Run the dashboard server
    try:
        socketio.run(
            app,
            host="0.0.0.0",
            port=5002,
            debug=True,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )
    except KeyboardInterrupt:
        print("\n🛑 Dashboard server stopped")
