#!/usr/bin/env python3
"""
Live Timestomping Monitor - FastAPI Backend
Real-time monitoring system with WebSocket support for Next.js frontend
"""

import os
import sys
import json
import time
import threading
import datetime
import asyncio
from pathlib import Path
from typing import Dict, List, Set, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Import our detection components
from mft_analyzer import MFTAnalyzer
from usn_parser import USNJournalParser
from logfile_parser import analyze_tampering

# Pydantic models for API requests/responses
class MonitorPathRequest(BaseModel):
    path: str

class MonitorPathResponse(BaseModel):
    success: bool
    message: str
    paths: List[str]

class MonitoringStatusResponse(BaseModel):
    is_monitoring: bool
    paths: List[str]
    total_alerts: int
    recent_alerts: List[Dict]

class AlertResponse(BaseModel):
    timestamp: str
    file_path: str
    event_type: str
    risk_score: int
    risk_level: str
    discrepancies: List[str]
    si_timestamps: Dict
    fn_timestamps: Dict
    alert_id: int

class LogFileAnalysisResponse(BaseModel):
    success: bool
    message: str
    total_pages: int
    total_records: int
    inode_count: int
    tampering_evidence_count: int
    high_risk_indicators_count: int
    analysis_results: Dict
    tampering_evidence: List[Dict]
    high_risk_indicators: List[Dict]

class ConnectionManager:
    """Manages WebSocket connections"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_json(message)

    async def broadcast(self, message: dict):
        for connection in self.active_connections[:]:  # Create a copy to iterate
            try:
                await connection.send_json(message)
            except:
                # Connection might be closed, remove it
                if connection in self.active_connections:
                    self.active_connections.remove(connection)

# Global connection manager
manager = ConnectionManager()

# Background task main loop reference
main_loop = None

# FastAPI app
app = FastAPI(title="Live Timestomping Monitor API", version="1.0.0")

@app.on_event("startup")
async def startup_event():
    global main_loop
    main_loop = asyncio.get_running_loop()

# CORS middleware for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Next.js default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TimestompEventHandler(FileSystemEventHandler):
    """Handles file system events for timestomping detection"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.mft_analyzer = MFTAnalyzer()
        self.usn_parser = USNJournalParser(monitor.get_volume_path())
        
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self.monitor.analyze_file_change(event.src_path, "modified")
            
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self.monitor.analyze_file_change(event.src_path, "created")
            
    def on_moved(self, event):
        """Handle file move/rename events"""
        if not event.is_directory:
            self.monitor.analyze_file_change(event.dest_path, "moved")

class LiveTimestompMonitor:
    """Real-time timestomping detection system"""
    
    def __init__(self):
        self.observers = []
        self.monitored_paths = []
        self.suspicious_files = []
        self.alerts = []
        self.is_monitoring = False
        self.mft_analyzer = MFTAnalyzer()
        self.usn_parser = USNJournalParser(self.get_volume_path())
        
        # File type filters - Empty set means monitor all files
        self.monitored_extensions = set()  # Monitor all file types
        
        # Alternative: Monitor specific high-risk file types
        # self.monitored_extensions = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.pdf', '.doc', '.docx', '.xls', '.xlsx'}
        
        # Alert thresholds
        self.time_discrepancy_threshold = 3600  # 1 hour in seconds
        self.risk_score_threshold = 30
        
        # Periodic scanning for timestamp changes
        self.scan_interval = 5  # seconds
        self.file_timestamps = {}  # Cache of last seen timestamps
        self.scanning_thread = None
        
    def get_volume_path(self):
        """Get system volume path"""
        current_dir = os.getcwd()
        if len(current_dir) >= 2 and current_dir[1] == ':':
            return current_dir[0].upper()
        return 'C'
        
    def set_monitored_extensions(self, extensions: set):
        """Set which file extensions to monitor (empty set = all files)"""
        self.monitored_extensions = extensions
        
    def add_monitored_extension(self, extension: str):
        """Add a file extension to monitor"""
        self.monitored_extensions.add(extension.lower())
        
    def remove_monitored_extension(self, extension: str):
        """Remove a file extension from monitoring"""
        self.monitored_extensions.discard(extension.lower())
        
    def add_monitor_path(self, path: str):
        """Add a directory to monitor"""
        if os.path.exists(path) and path not in self.monitored_paths:
            self.monitored_paths.append(path)
            return True
        return False
        
    def remove_monitor_path(self, path: str):
        """Remove a directory from monitoring"""
        if path in self.monitored_paths:
            self.monitored_paths.remove(path)
            return True
        return False
        
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_monitoring:
            return False
            
        try:
            # Create observers for each monitored path
            for path in self.monitored_paths:
                event_handler = TimestompEventHandler(self)
                observer = Observer()
                observer.schedule(event_handler, path, recursive=True)
                observer.start()
                self.observers.append(observer)
                
            # Start periodic scanning thread
            self.scanning_thread = threading.Thread(target=self._periodic_scan, daemon=True)
            self.scanning_thread.start()
                
            self.is_monitoring = True
            return True
            
        except Exception as e:
            print(f"Error starting monitoring: {e}")
            return False
            
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        if not self.is_monitoring:
            return
            
        for observer in self.observers:
            observer.stop()
            observer.join()
            
        self.observers.clear()
        self.is_monitoring = False
        self.scanning_thread = None
        
    def _periodic_scan(self):
        """Periodically scan for timestamp changes"""
        while self.is_monitoring:
            try:
                for path in self.monitored_paths:
                    self._scan_directory_for_changes(path)
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"Error in periodic scan: {e}")
                time.sleep(self.scan_interval)
                
    def _scan_directory_for_changes(self, directory: str):
        """Scan directory for timestamp changes"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check if file should be monitored
                    if self.monitored_extensions:
                        ext = Path(file_path).suffix.lower()
                        if ext not in self.monitored_extensions:
                            continue
                            
                    try:
                        # Get current file stats
                        stat_info = os.stat(file_path)
                        current_timestamps = {
                            'creation': stat_info.st_ctime,
                            'modification': stat_info.st_mtime,
                            'access': stat_info.st_atime
                        }
                        
                        # Check if we've seen this file before
                        file_key = file_path.lower()
                        if file_key in self.file_timestamps:
                            # Compare with cached timestamps
                            old_timestamps = self.file_timestamps[file_key]
                            
                            # Check for significant changes
                            for ts_type in ['creation', 'modification', 'access']:
                                old_time = old_timestamps.get(ts_type, 0)
                                new_time = current_timestamps[ts_type]
                                
                                # If timestamp changed significantly (more than 1 hour difference)
                                if abs(new_time - old_time) > 3600:
                                    print(f"🔍 Detected timestamp change in {file_path}")
                                    # Run analysis
                                    self.analyze_file_change(file_path, "timestamp_modified")
                                    break
                        
                        # Update cache
                        self.file_timestamps[file_key] = current_timestamps
                        
                    except (OSError, PermissionError):
                        # Skip files that can't be accessed
                        continue
                        
        except Exception as e:
            print(f"Error scanning directory {directory}: {e}")
        
    def analyze_file_change(self, file_path: str, event_type: str):
        """Analyze a file for timestomping after a change event"""
        try:
            # Skip if not a monitored file type (only if extensions are specified)
            if self.monitored_extensions:
                file_ext = Path(file_path).suffix.lower()
                if file_ext not in self.monitored_extensions:
                    return
                
            # Get current file state
            current_analysis = self.mft_analyzer.extract_timestamps(file_path)
            
            if 'error' in current_analysis:
                return
                
            # Check for suspicious patterns
            risk_score = self.calculate_risk_score(current_analysis, file_path)
            
            if risk_score >= self.risk_score_threshold:
                alert = self.create_alert(file_path, current_analysis, risk_score, event_type)
                self.alerts.append(alert)
                self.suspicious_files.append(file_path)
                
                # Broadcast alert via WebSocket safely
                global main_loop
                if main_loop and main_loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        manager.broadcast({
                            "type": "alert",
                            "data": alert
                        }), main_loop)
                
                # Also print to console
                self.print_alert(alert)
                
        except Exception as e:
            print(f"Error analyzing file change {file_path}: {e}")
            
    def calculate_risk_score(self, analysis: Dict, file_path: str) -> int:
        """Calculate risk score for file analysis"""
        score = 0
        
        # Check timestamp discrepancies
        discrepancies = analysis.get('discrepancies', [])
        score += len(discrepancies) * 20
        
        # Check file name for suspicious patterns
        filename = os.path.basename(file_path).lower()
        suspicious_names = ['malware', 'virus', 'trojan', 'backdoor', 'rootkit', 'hack']
        for susp in suspicious_names:
            if susp in filename:
                score += 30
                
        # Check file location
        if 'system32' in file_path.lower() or 'windows' in file_path.lower():
            score += 15
            
        # Check file extension
        ext = Path(file_path).suffix.lower()
        if ext in {'.exe', '.sys', '.scr'}:
            score += 10
            
        return score
        
    def create_alert(self, file_path: str, analysis: Dict, risk_score: int, event_type: str) -> Dict:
        """Create an alert for suspicious activity"""
        return {
            'timestamp': datetime.datetime.now().isoformat(),
            'file_path': file_path,
            'event_type': event_type,
            'risk_score': risk_score,
            'risk_level': 'high' if risk_score >= 70 else 'medium',
            'discrepancies': analysis.get('discrepancies', []),
            'si_timestamps': analysis.get('si_timestamps', {}),
            'fn_timestamps': analysis.get('fn_timestamps', {}),
            'alert_id': len(self.alerts) + 1
        }
        
    def print_alert(self, alert: Dict):
        """Print alert to console"""
        print(f"\n🚨 TIMESTOMPING ALERT [{alert['alert_id']}]")
        print(f"⏰ Time: {alert['timestamp']}")
        print(f"📁 File: {alert['file_path']}")
        print(f"🔄 Event: {alert['event_type'].upper()}")
        print(f"⚠️  Risk Level: {alert['risk_level'].upper()} (Score: {alert['risk_score']})")
        
        if alert['discrepancies']:
            print("🔍 Discrepancies:")
            for disc in alert['discrepancies']:
                print(f"   • {disc}")
                
        print("-" * 60)
        
    def get_recent_alerts(self, hours: int = 1) -> List[Dict]:
        """Get alerts from the last N hours"""
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
        recent_alerts = []
        
        for alert in self.alerts:
            alert_time = datetime.datetime.fromisoformat(alert['timestamp'])
            if alert_time >= cutoff_time:
                recent_alerts.append(alert)
                
        return recent_alerts
        
    def export_alerts(self, filename: str = None):
        """Export alerts to JSON file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"timestomp_alerts_{timestamp}.json"
            
        export_data = {
            'export_time': datetime.datetime.now().isoformat(),
            'total_alerts': len(self.alerts),
            'monitoring_paths': self.monitored_paths,
            'alerts': self.alerts
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
            
        return filename

# Global monitor instance
monitor = LiveTimestompMonitor()

# API Routes
@app.get("/", response_model=dict)
async def root():
    return {"message": "Live Timestomping Monitor API", "version": "1.0.0"}

@app.get("/status", response_model=MonitoringStatusResponse)
async def get_status():
    """Get current monitoring status"""
    recent_alerts = monitor.get_recent_alerts(1)
    return MonitoringStatusResponse(
        is_monitoring=monitor.is_monitoring,
        paths=monitor.monitored_paths.copy(),
        total_alerts=len(monitor.alerts),
        recent_alerts=recent_alerts
    )

@app.post("/paths/add", response_model=MonitorPathResponse)
async def add_path(request: MonitorPathRequest):
    """Add a path to monitor"""
    success = monitor.add_monitor_path(request.path)
    return MonitorPathResponse(
        success=success,
        message=f"Path {'added' if success else 'failed to add'}: {request.path}",
        paths=monitor.monitored_paths.copy()
    )

@app.delete("/paths/{path}", response_model=MonitorPathResponse)
async def remove_path(path: str):
    """Remove a path from monitoring"""
    success = monitor.remove_monitor_path(path)
    return MonitorPathResponse(
        success=success,
        message=f"Path {'removed' if success else 'failed to remove'}: {path}",
        paths=monitor.monitored_paths.copy()
    )

@app.get("/paths", response_model=List[str])
async def get_paths():
    """Get all monitored paths"""
    return monitor.monitored_paths.copy()

@app.post("/monitoring/start")
async def start_monitoring():
    """Start monitoring"""
    success = monitor.start_monitoring()
    if success:
        await manager.broadcast({
            "type": "status",
            "data": {
                "is_monitoring": True,
                "message": "Monitoring started"
            }
        })
        return {"success": True, "message": "Monitoring started"}
    else:
        raise HTTPException(status_code=400, detail="Failed to start monitoring")

@app.post("/monitoring/stop")
async def stop_monitoring():
    """Stop monitoring"""
    monitor.stop_monitoring()
    await manager.broadcast({
        "type": "status",
        "data": {
            "is_monitoring": False,
            "message": "Monitoring stopped"
        }
    })
    return {"success": True, "message": "Monitoring stopped"}

@app.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(limit: int = 100):
    """Get recent alerts"""
    alerts = monitor.alerts.copy()
    return alerts[-limit:] if len(alerts) > limit else alerts

@app.get("/alerts/export")
async def export_alerts():
    """Export alerts to JSON"""
    filename = monitor.export_alerts()
    return {"success": True, "filename": filename, "message": f"Alerts exported to {filename}"}

@app.post("/logfile/analyze", response_model=LogFileAnalysisResponse)
async def analyze_logfile(file: UploadFile = File(...)):
    """
    Upload and analyze NTFS $LogFile for timestamp tampering evidence
    """
    try:
        # Validate file type
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
            
        # Check file extension (optional, but helpful)
        if not (file.filename.endswith('.bin') or file.filename.endswith('.logfile') or file.filename.lower() == 'logfile'):
            # Still allow it, but note the warning
            pass
        
        # Create temporary file
        temp_dir = "temp_uploads"
        os.makedirs(temp_dir, exist_ok=True)
        
        temp_file_path = os.path.join(temp_dir, f"logfile_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
        
        # Save uploaded file
        try:
            with open(temp_file_path, "wb") as temp_file:
                content = await file.read()
                temp_file.write(content)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {str(e)}")
        
        # Analyze the logfile
        try:
            analysis_results = analyze_tampering(temp_file_path)
            
            # Prepare response
            response = LogFileAnalysisResponse(
                success=True,
                message="LogFile analysis completed successfully",
                total_pages=analysis_results.get('total_pages', 0),
                total_records=analysis_results.get('total_records', 0),
                inode_count=len(analysis_results.get('inode_timeline', {})),
                tampering_evidence_count=analysis_results.get('evidence_count', 0),
                high_risk_indicators_count=len(analysis_results.get('high_risk_indicators', [])),
                analysis_results=analysis_results,
                tampering_evidence=analysis_results.get('tampering_evidence', []),
                high_risk_indicators=analysis_results.get('high_risk_indicators', [])
            )
            
            # Broadcast alert if high-risk indicators found
            if analysis_results.get('high_risk_indicators'):
                await manager.broadcast({
                    "type": "logfile_alert",
                    "data": {
                        "message": f"High-risk timestamp tampering detected in {file.filename}",
                        "evidence_count": len(analysis_results.get('high_risk_indicators', [])),
                        "filename": file.filename,
                        "analysis_time": datetime.datetime.now().isoformat()
                    }
                })
            
            return response
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to analyze logfile: {str(e)}")
            
        finally:
            # Clean up temporary file
            try:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
            except:
                pass  # Ignore cleanup errors
                
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/logfile/info")
async def get_logfile_info():
    """
    Get information about $LogFile analysis capabilities
    """
    return {
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

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial status
        await manager.send_personal_message({
            "type": "status",
            "data": {
                "is_monitoring": monitor.is_monitoring,
                "paths": monitor.monitored_paths.copy(),
                "total_alerts": len(monitor.alerts),
                "recent_alerts": monitor.get_recent_alerts(1)
            }
        }, websocket)
        
        # Keep connection alive and handle incoming messages
        while True:
            data = await websocket.receive_text()
            # Handle any client messages if needed
            message = json.loads(data)
            
            if message.get("type") == "ping":
                await manager.send_personal_message({"type": "pong"}, websocket)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)

def main():
    """Main function to start the FastAPI server"""
    import uvicorn
    
    print("🔴 LIVE TIMESTOMPING MONITOR API")
    print("=" * 60)
    print("🚀 Starting FastAPI server...")
    print("📡 WebSocket endpoint: ws://localhost:8080/ws")
    print("🌐 API docs: http://localhost:8080/docs")
    print("=" * 60)
    
    # Add default monitoring paths
    default_paths = [
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Program Files",
        os.path.expanduser("~/Desktop")
    ]
    
    for path in default_paths:
        if os.path.exists(path):
            monitor.add_monitor_path(path)
            print(f"📁 Added default path: {path}")
    
    print("\n🔴 Server ready for Next.js frontend connection!")
    
    # Start the server
    uvicorn.run("live_monitor_api:app", host="0.0.0.0", port=8080, reload=True)

if __name__ == '__main__':
    main()
