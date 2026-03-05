# Live Timestomping Monitor - FastAPI Backend

This is the FastAPI backend for the Live Timestomping Monitor, designed to work with a Next.js frontend via WebSockets.

## Features

- **Real-time Monitoring**: Detects timestomping attempts as they happen
- **WebSocket Communication**: Live alerts broadcasted to connected clients
- **RESTful API**: Full control over monitoring operations
- **CORS Support**: Ready for Next.js frontend integration
- **Automatic Documentation**: Interactive API docs at `/docs`

## Installation

```bash
pip install -r requirements.txt
```

## Running the Server

```bash
python live_monitor_api.py
```

The server will start on `http://localhost:8000`

## API Endpoints

### WebSocket Connection
- **Endpoint**: `ws://localhost:8000/ws`
- **Purpose**: Real-time alerts and status updates

### REST API Endpoints

#### Monitoring Control
- `POST /monitoring/start` - Start monitoring
- `POST /monitoring/stop` - Stop monitoring
- `GET /status` - Get current monitoring status

#### Path Management
- `GET /paths` - Get all monitored paths
- `POST /paths/add` - Add a path to monitor
- `DELETE /paths/{path}` - Remove a path from monitoring

#### Alerts
- `GET /alerts` - Get recent alerts (with optional `limit` parameter)
- `GET /alerts/export` - Export alerts to JSON file

#### General
- `GET /` - API info
- `GET /docs` - Interactive API documentation

## WebSocket Message Format

### Alert Messages
```json
{
  "type": "alert",
  "data": {
    "timestamp": "2024-01-01T12:00:00",
    "file_path": "C:\\Windows\\System32\\suspicious.exe",
    "event_type": "modified",
    "risk_score": 45,
    "risk_level": "medium",
    "discrepancies": ["SI modification time differs from FN modification time"],
    "si_timestamps": {...},
    "fn_timestamps": {...},
    "alert_id": 1
  }
}
```

### Status Messages
```json
{
  "type": "status",
  "data": {
    "is_monitoring": true,
    "paths": ["C:\\Windows\\System32"],
    "total_alerts": 5,
    "recent_alerts": [...]
  }
}
```

## Next.js Integration

### Client-side WebSocket Connection

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  if (message.type === 'alert') {
    // Handle new alert
    console.log('New timestomping alert:', message.data);
  } else if (message.type === 'status') {
    // Handle status update
    console.log('Status update:', message.data);
  }
};

// Send ping to keep connection alive
setInterval(() => {
  ws.send(JSON.stringify({ type: 'ping' }));
}, 30000);
```

### API Calls Example

```javascript
// Start monitoring
const startMonitoring = async () => {
  const response = await fetch('http://localhost:8000/monitoring/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  });
  return response.json();
};

// Add monitoring path
const addPath = async (path) => {
  const response = await fetch('http://localhost:8000/paths/add', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path })
  });
  return response.json();
};

// Get alerts
const getAlerts = async (limit = 100) => {
  const response = await fetch(`http://localhost:8000/alerts?limit=${limit}`);
  return response.json();
};
```

## Default Monitoring Paths

The server automatically adds these default paths on startup:
- `C:\Windows\System32`
- `C:\Windows\SysWOW64`
- `C:\Program Files`
- User's Desktop

## Risk Scoring

Alerts are generated based on:
- **Timestamp discrepancies**: +20 points each
- **Suspicious filenames**: +30 points (malware, virus, trojan, etc.)
- **System locations**: +15 points (system32, windows folders)
- **Risky extensions**: +10 points (.exe, .sys, .scr)

Default threshold: 30 points

## Development

The server runs with `reload=True` for development. Changes to the code will automatically restart the server.

## Production Deployment

For production, consider:
1. Using a production-grade ASGI server
2. Implementing authentication/authorization
3. Adding rate limiting
4. Setting up proper logging
5. Using HTTPS/WSS protocols
