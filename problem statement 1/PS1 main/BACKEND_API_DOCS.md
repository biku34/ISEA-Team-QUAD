# Live Timestomping Monitor - Backend API Documentation

## Overview

This document provides comprehensive documentation for the FastAPI backend that provides real-time timestomping detection and $LogFile analysis capabilities.

**Base URL**: `http://localhost:8000`  
**API Version**: `1.0.0`  
**WebSocket**: `ws://localhost:8000/ws`

## Authentication

Currently, the API does not implement authentication. In production, consider implementing:
- JWT tokens for API endpoints
- WebSocket authentication
- Rate limiting
- API key management

## CORS Configuration

The backend is configured to accept requests from:
- `http://localhost:3000` (Next.js default)
- `http://127.0.0.1:3000`

## API Endpoints

### 1. System Information

#### GET `/`
Get basic API information and version.

**Response:**
```json
{
  "message": "Live Timestomping Monitor API",
  "version": "1.0.0"
}
```

---

### 2. Monitoring Status

#### GET `/status`
Get current monitoring system status including active paths and alert statistics.

**Response:**
```json
{
  "is_monitoring": true,
  "paths": [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64"
  ],
  "total_alerts": 15,
  "recent_alerts": [
    {
      "timestamp": "2024-03-01T10:30:00.000Z",
      "file_path": "C:\\Windows\\System32\\suspicious.exe",
      "event_type": "modified",
      "risk_score": 45,
      "risk_level": "medium",
      "discrepancies": ["SI modification time differs from FN modification time"],
      "si_timestamps": {...},
      "fn_timestamps": {...},
      "alert_id": 1
    }
  ]
}
```

**Response Schema:**
- `is_monitoring` (boolean): Whether real-time monitoring is active
- `paths` (string[]): List of currently monitored paths
- `total_alerts` (integer): Total number of alerts generated
- `recent_alerts` (object[]): Alerts from the last hour

---

### 3. Path Management

#### GET `/paths`
Get all currently monitored paths.

**Response:**
```json
[
  "C:\\Windows\\System32",
  "C:\\Windows\\SysWOW64",
  "C:\\Program Files",
  "C:\\Users\\User\\Desktop"
]
```

#### POST `/paths/add`
Add a new path to the monitoring system.

**Request Body:**
```json
{
  "path": "C:\\Custom\\Path"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Path added: C:\\Custom\\Path",
  "paths": [
    "C:\\Windows\\System32",
    "C:\\Custom\\Path"
  ]
}
```

**Error Response (400):**
```json
{
  "detail": "Failed to add path: C:\\Invalid\\Path"
}
```

#### DELETE `/paths/{path}`
Remove a path from monitoring. Path must be URL-encoded.

**Example:** `DELETE /paths/C%3A%5CWindows%5CSystem32`

**Response:**
```json
{
  "success": true,
  "message": "Path removed: C:\\Windows\\System32",
  "paths": ["C:\\Windows\\SysWOW64"]
}
```

---

### 4. Monitoring Control

#### POST `/monitoring/start`
Start the real-time monitoring system.

**Response:**
```json
{
  "success": true,
  "message": "Monitoring started"
}
```

**Error Response (400):**
```json
{
  "detail": "Failed to start monitoring"
}
```

#### POST `/monitoring/stop`
Stop the real-time monitoring system.

**Response:**
```json
{
  "success": true,
  "message": "Monitoring stopped"
}
```

---

### 5. Alert Management

#### GET `/alerts`
Get recent alerts with optional limit parameter.

**Query Parameters:**
- `limit` (optional, integer): Maximum number of alerts to return (default: 100)

**Example:** `GET /alerts?limit=50`

**Response:**
```json
[
  {
    "timestamp": "2024-03-01T10:30:00.000Z",
    "file_path": "C:\\Windows\\System32\\suspicious.exe",
    "event_type": "modified",
    "risk_score": 45,
    "risk_level": "medium",
    "discrepancies": [
      "SI modification time differs from FN modification time",
      "Creation time inconsistent across MFT entries"
    ],
    "si_timestamps": {
      "creation_time": "2024-03-01T09:00:00.000Z",
      "modification_time": "2024-03-01T10:30:00.000Z",
      "mft_change_time": "2024-03-01T10:30:00.000Z",
      "access_time": "2024-03-01T10:30:00.000Z"
    },
    "fn_timestamps": {
      "creation_time": "2024-03-01T09:00:00.000Z",
      "modification_time": "2024-03-01T10:30:00.000Z"
    },
    "alert_id": 1
  }
]
```

#### GET `/alerts/export`
Export all alerts to a JSON file.

**Response:**
```json
{
  "success": true,
  "filename": "timestomp_alerts_20240301_103045.json",
  "message": "Alerts exported to: timestomp_alerts_20240301_103045.json"
}
```

---

### 6. $LogFile Analysis

#### POST `/logfile/analyze`
Upload and analyze NTFS $LogFile for timestamp tampering evidence.

**Request:** `multipart/form-data`
- `file` (file): $LogFile binary file (.bin, .logfile, or any extension)

**File Size Limit:** 100MB

**Response:**
```json
{
  "success": true,
  "message": "LogFile analysis completed successfully",
  "total_pages": 1024,
  "total_records": 15420,
  "inode_count": 89,
  "tampering_evidence_count": 3,
  "high_risk_indicators_count": 2,
  "analysis_results": {
    "total_pages": 1024,
    "total_records": 15420,
    "inode_count": 89,
    "lsn_min": 12345,
    "lsn_max": 678901,
    "events_by_inode": {
      "12345": [
        {
          "lsn": 12350,
          "redo_op": 7,
          "undo_op": 0,
          "si_timestamps": [
            "2024-03-01T09:00:00.000Z",
            "2024-03-01T10:30:00.000Z",
            "2024-03-01T10:30:00.000Z",
            "2024-03-01T10:30:00.000Z"
          ],
          "is_set_basic_info": true
        }
      ]
    },
    "tampering_evidence": [
      {
        "inode": 12345,
        "type": "rapid_timestamp_change",
        "severity": "high",
        "description": "Rapid timestamp modification detected for inode 12345",
        "events": [
          {
            "lsn": 12349,
            "operation": "SetBasicInformation",
            "timestamps": ["2024-03-01T09:00:00.000Z", "2024-03-01T10:30:00.000Z"]
          },
          {
            "lsn": 12350,
            "operation": "SetBasicInformation", 
            "timestamps": ["2024-03-01T09:00:00.000Z", "2024-03-01T15:45:00.000Z"]
          }
        ],
        "time_difference": {
          "seconds": 18675,
          "lsn_difference": 1
        }
      }
    ],
    "evidence_count": 3,
    "high_risk_indicators": [...],
    "parsing_timestamp": "2024-03-01T10:30:00.000Z"
  },
  "tampering_evidence": [
    {
      "inode": 12345,
      "type": "rapid_timestamp_change",
      "severity": "high",
      "description": "Rapid timestamp modification detected for inode 12345",
      "events": [...],
      "time_difference": {
        "seconds": 18675,
        "lsn_difference": 1
      }
    }
  ],
  "high_risk_indicators": [
    {
      "inode": 12345,
      "type": "rapid_timestamp_change",
      "severity": "high",
      "description": "Rapid timestamp modification detected for inode 12345",
      "events": [...],
      "time_difference": {
        "seconds": 18675,
        "lsn_difference": 1
      }
    }
  ]
}
```

**Error Response (400):**
```json
{
  "detail": "Failed to save uploaded file: File too large"
}
```

**Error Response (500):**
```json
{
  "detail": "Failed to analyze logfile: Invalid $LogFile format"
}
```

#### GET `/logfile/info`
Get information about $LogFile analysis capabilities and supported operations.

**Response:**
```json
{
  "description": "NTFS $LogFile Parser for Timestamp Tampering Detection",
  "capabilities": [
    "Parse $LogFile binary structure (4KB pages)",
    "Apply Update Sequence Array (USA) fixup for torn write detection",
    "Extract timestamps from SetNewAttributeValue (0x05) operations",
    "Extract timestamps from UpdateResidentValue (0x07) operations",
    "Convert Windows FILETIME to UTC datetime",
    "Build chronological timeline by inode number",
    "Detect rapid timestamp changes",
    "Detect impossible timestamp sequences",
    "Identify anti-forensics tool usage"
  ],
  "supported_operations": [
    {
      "code": "0x05",
      "name": "SetNewAttributeValue",
      "description": "Setting new file attribute values"
    },
    {
      "code": "0x07",
      "name": "UpdateResidentValue",
      "description": "Updating resident attribute values"
    }
  ],
  "evidence_types": [
    "rapid_timestamp_change",
    "impossible_timestamp",
    "anti_forensics_tool_usage"
  ],
  "usage": "Upload $LogFile binary extracted using: icat -o <offset> <image> 2 > logfile.bin"
}
```

---

## WebSocket API

### Connection

#### WebSocket `/ws`
Real-time bidirectional communication for live alerts and status updates.

**Connection URL:** `ws://localhost:8000/ws`

### Message Types

#### 1. Status Updates
Sent when monitoring state changes or on initial connection.

**Message Format:**
```json
{
  "type": "status",
  "data": {
    "is_monitoring": true,
    "paths": ["C:\\Windows\\System32"],
    "total_alerts": 15,
    "recent_alerts": [...]
  }
}
```

#### 2. Real-time Alerts
Sent immediately when timestomping is detected.

**Message Format:**
```json
{
  "type": "alert",
  "data": {
    "timestamp": "2024-03-01T10:30:00.000Z",
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

#### 3. LogFile Analysis Alerts
Sent when high-risk indicators are found during $LogFile analysis.

**Message Format:**
```json
{
  "type": "logfile_alert",
  "data": {
    "message": "High-risk timestamp tampering detected in sample.bin",
    "evidence_count": 2,
    "filename": "sample.bin",
    "analysis_time": "2024-03-01T10:30:00.000Z"
  }
}
```

#### 4. Ping/Pong
Keep-alive mechanism for connection health.

**Client Send:**
```json
{
  "type": "ping"
}
```

**Server Response:**
```json
{
  "type": "pong"
}
```

---

## Data Models

### Alert Object

```typescript
interface Alert {
  timestamp: string;           // ISO 8601 timestamp
  file_path: string;         // Full file path
  event_type: string;        // "created", "modified", "moved", "timestamp_modified"
  risk_score: number;        // 0-100+ risk assessment
  risk_level: string;        // "low", "medium", "high"
  discrepancies: string[];     // List of detected issues
  si_timestamps: {          // Standard Information timestamps
    creation_time: string;
    modification_time: string;
    mft_change_time: string;
    access_time: string;
  };
  fn_timestamps: {          // File Name timestamps
    creation_time: string;
    modification_time: string;
  };
  alert_id: number;          // Sequential alert ID
}
```

### LogFile Analysis Evidence

```typescript
interface TamperingEvidence {
  inode: number;                    // MFT inode number
  type: string;                     // "rapid_timestamp_change", "impossible_timestamp"
  severity: string;                  // "high", "medium", "low"
  description: string;                // Human-readable description
  events: LogFileEvent[];          // Related log events
  time_difference?: {               // For rapid changes
    seconds: number;               // Time difference in seconds
    lsn_difference: number;         // LSN distance between events
  };
  timestamps?: {                    // For impossible timestamps
    creation_time: string;
    modification_time: string;
  };
}
```

### LogFile Event

```typescript
interface LogFileEvent {
  lsn: number;                        // Log Sequence Number
  redo_op: number;                     // NTFS operation code
  undo_op: number;                     // Undo operation code
  si_timestamps: string[];             // Extracted FILETIME values
  is_set_basic_info: boolean;           // True for SetBasicInformation ops
}
```

---

## Error Handling

### HTTP Status Codes

- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters or data
- `500 Internal Server Error`: Server-side processing error

### Error Response Format

```json
{
  "detail": "Human-readable error message"
}
```

### Common Error Scenarios

1. **File Upload Errors**
   - File too large (>100MB)
   - Invalid file format
   - Corrupted $LogFile structure

2. **Monitoring Errors**
   - No paths configured
   - Insufficient permissions
   - File system access denied

3. **WebSocket Errors**
   - Connection refused
   - Authentication failed
   - Rate limit exceeded

---

## Rate Limiting

Currently not implemented, but recommended for production:
- API endpoints: 100 requests/minute
- File uploads: 10 uploads/minute
- WebSocket connections: 5 connections/IP

---

## Security Considerations

### Current Implementation
- CORS configured for localhost development
- No authentication required
- File upload validation by size and basic type checking

### Production Recommendations
1. **Authentication**
   - JWT-based API authentication
   - WebSocket token authentication
   - Role-based access control

2. **Input Validation**
   - Strict file type validation
   - Malware scanning for uploads
   - Path traversal prevention

3. **Rate Limiting**
   - Implement per-IP rate limits
   - Distributed rate limiting for clusters

4. **Logging**
   - Comprehensive audit logging
   - Security event monitoring
   - Anomaly detection

5. **Data Protection**
   - HTTPS enforcement
   - Secure file handling
   - Temporary file cleanup
   - Memory usage limits

---

## Performance Considerations

### Memory Usage
- Real-time monitoring: ~50-100MB base memory
- $LogFile analysis: ~2x file size during processing
- WebSocket connections: ~1MB per 1000 connections

### CPU Usage
- File system monitoring: Low impact
- $LogFile parsing: CPU intensive during analysis
- Alert processing: Minimal impact

### Storage
- Temporary files: Automatic cleanup after upload
- Alert exports: User-managed cleanup
- Log rotation: Implement for long-running systems

---

## Monitoring and Health Checks

### Health Endpoint
Consider adding `/health` endpoint:
```json
{
  "status": "healthy",
  "timestamp": "2024-03-01T10:30:00.000Z",
  "version": "1.0.0",
  "uptime": 3600,
  "active_connections": 3,
  "monitoring_active": true
}
```

### Metrics to Track
- Request rate per endpoint
- Average response times
- Error rates by type
- WebSocket connection count
- Memory and CPU usage
- $LogFile processing statistics

---

## Integration Examples

### cURL Examples

**Get Status:**
```bash
curl -X GET "http://localhost:8000/status" \
  -H "Content-Type: application/json"
```

**Add Monitoring Path:**
```bash
curl -X POST "http://localhost:8000/paths/add" \
  -H "Content-Type: application/json" \
  -d '{"path": "C:\\Custom\\Path"}'
```

**Start Monitoring:**
```bash
curl -X POST "http://localhost:8000/monitoring/start" \
  -H "Content-Type: application/json"
```

**Upload $LogFile:**
```bash
curl -X POST "http://localhost:8000/logfile/analyze" \
  -F "file=@sample.bin" \
  -H "Accept: application/json"
```

### JavaScript/Fetch Examples

```javascript
// Get monitoring status
const response = await fetch('http://localhost:8000/status');
const status = await response.json();

// Upload $LogFile
const formData = new FormData();
formData.append('file', logfileFile);

const uploadResponse = await fetch('http://localhost:8000/logfile/analyze', {
  method: 'POST',
  body: formData
});
const results = await uploadResponse.json();
```

### WebSocket Connection

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  switch(message.type) {
    case 'alert':
      console.log('New timestomping alert:', message.data);
      break;
    case 'status':
      console.log('Status update:', message.data);
      break;
    case 'logfile_alert':
      console.log('LogFile analysis alert:', message.data);
      break;
  }
};

// Keep alive
setInterval(() => {
  ws.send(JSON.stringify({type: 'ping'}));
}, 30000);
```

---

## Deployment

### Development
```bash
python live_monitor_api.py
```

### Production (with Gunicorn)
```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker live_monitor_api:app --bind 0.0.0.0:8000
```

### Docker
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "live_monitor_api.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  timestomp-monitor:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - PYTHONUNBUFFERED=1
```

---

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   - Error: `Address already in use`
   - Solution: Change port or kill existing process

2. **Permission Denied**
   - Error: `Access denied` when monitoring system paths
   - Solution: Run as administrator

3. **$LogFile Upload Fails**
   - Error: `Failed to analyze logfile`
   - Solution: Verify file integrity and format

4. **WebSocket Connection Fails**
   - Error: `Connection refused`
   - Solution: Check CORS settings and firewall

### Debug Mode

Enable debug logging by setting environment variable:
```bash
export LOG_LEVEL=DEBUG
python live_monitor_api.py
```

### Log Files
- Application logs: Console output
- Error logs: Console with `[ERROR]` prefix
- Access logs: Implement for production (recommended)

---

## API Versioning

The API follows semantic versioning:
- **Major**: Breaking changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, backward compatible

Current version: `1.0.0`

### Backward Compatibility
- Endpoints may be deprecated with advance notice
- Response formats will remain stable
- WebSocket message format is versioned

---

## Support and Contributing

### Getting Help
- Review this documentation
- Check console error messages
- Verify network connectivity
- Test with sample data

### Contributing
- Fork the repository
- Follow coding standards
- Add comprehensive tests
- Update documentation

---

*This documentation covers the complete backend API for the Live Timestomping Monitor system.*
