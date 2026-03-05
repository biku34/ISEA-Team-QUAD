# Next.js Frontend Documentation

This guide provides comprehensive documentation for building a Next.js frontend to interact with the Live Timestomping Monitor FastAPI backend.

## Overview

The frontend connects to the FastAPI backend via:
- **WebSocket** (`ws://localhost:8000/ws`) for real-time alerts and status updates
- **REST API** (`http://localhost:8000`) for monitoring control operations

## Prerequisites

- Next.js 13+ (with App Router recommended)
- TypeScript (recommended)
- WebSocket client support
- Axios or fetch for API calls

## Project Setup

### 1. Create Next.js Project

```bash
npx create-next-app@latest timestomp-monitor-frontend --typescript --tailwind --app
cd timestomp-monitor-frontend
```

### 2. Install Dependencies

```bash
npm install axios
# or
yarn add axios
```

## Core Components

### 1. WebSocket Service

Create `lib/websocket.ts`:

```typescript
interface AlertData {
  timestamp: string;
  file_path: string;
  event_type: string;
  risk_score: number;
  risk_level: string;
  discrepancies: string[];
  si_timestamps: Record<string, any>;
  fn_timestamps: Record<string, any>;
  alert_id: number;
}

interface StatusData {
  is_monitoring: boolean;
  paths: string[];
  total_alerts: number;
  recent_alerts: AlertData[];
}

interface WebSocketMessage {
  type: 'alert' | 'status' | 'pong';
  data?: AlertData | StatusData;
}

type AlertHandler = (alert: AlertData) => void;
type StatusHandler = (status: StatusData) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private alertHandlers: AlertHandler[] = [];
  private statusHandlers: StatusHandler[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private pingInterval: NodeJS.Timeout | null = null;

  connect(url: string = 'ws://localhost:8000/ws') {
    try {
      this.ws = new WebSocket(url);
      
      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
        this.startPing();
      };

      this.ws.onmessage = (event) => {
        const message: WebSocketMessage = JSON.parse(event.data);
        
        switch (message.type) {
          case 'alert':
            this.alertHandlers.forEach(handler => handler(message.data as AlertData));
            break;
          case 'status':
            this.statusHandlers.forEach(handler => handler(message.data as StatusData));
            break;
          case 'pong':
            // Ping-pong successful
            break;
        }
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.stopPing();
        this.attemptReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      this.attemptReconnect();
    }
  }

  disconnect() {
    this.stopPing();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  private startPing() {
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000); // Ping every 30 seconds
  }

  private stopPing() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  private attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      
      setTimeout(() => {
        this.connect();
      }, this.reconnectDelay * this.reconnectAttempts);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }

  onAlert(handler: AlertHandler) {
    this.alertHandlers.push(handler);
  }

  onStatus(handler: StatusHandler) {
    this.statusHandlers.push(handler);
  }

  removeAlertHandler(handler: AlertHandler) {
    const index = this.alertHandlers.indexOf(handler);
    if (index > -1) {
      this.alertHandlers.splice(index, 1);
    }
  }

  removeStatusHandler(handler: StatusHandler) {
    const index = this.statusHandlers.indexOf(handler);
    if (index > -1) {
      this.statusHandlers.splice(index, 1);
    }
  }
}

export const wsService = new WebSocketService();
export type { AlertData, StatusData };
```

### 2. API Service

Create `lib/api.ts`:

```typescript
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Types
interface MonitorPathRequest {
  path: string;
}

interface MonitorPathResponse {
  success: boolean;
  message: string;
  paths: string[];
}

interface MonitoringStatusResponse {
  is_monitoring: boolean;
  paths: string[];
  total_alerts: number;
  recent_alerts: AlertData[];
}

interface AlertResponse {
  timestamp: string;
  file_path: string;
  event_type: string;
  risk_score: number;
  risk_level: string;
  discrepancies: string[];
  si_timestamps: Record<string, any>;
  fn_timestamps: Record<string, any>;
  alert_id: number;
}

interface LogFileAnalysisResponse {
  success: boolean;
  message: string;
  total_pages: number;
  total_records: number;
  inode_count: number;
  tampering_evidence_count: number;
  high_risk_indicators_count: number;
  analysis_results: Record<string, any>;
  tampering_evidence: Record<string, any>[];
  high_risk_indicators: Record<string, any>[];
}

interface LogFileInfoResponse {
  description: string;
  capabilities: string[];
  supported_operations: Array<{
    code: string;
    name: string;
    description: string;
  }>;
  evidence_types: string[];
  usage: string;
}

// API Functions
export const apiService = {
  // Status
  async getStatus(): Promise<MonitoringStatusResponse> {
    const response = await api.get('/status');
    return response.data;
  },

  // Monitoring Control
  async startMonitoring(): Promise<{ success: boolean; message: string }> {
    const response = await api.post('/monitoring/start');
    return response.data;
  },

  async stopMonitoring(): Promise<{ success: boolean; message: string }> {
    const response = await api.post('/monitoring/stop');
    return response.data;
  },

  // Path Management
  async getPaths(): Promise<string[]> {
    const response = await api.get('/paths');
    return response.data;
  },

  async addPath(path: string): Promise<MonitorPathResponse> {
    const response = await api.post('/paths/add', { path });
    return response.data;
  },

  async removePath(path: string): Promise<MonitorPathResponse> {
    const response = await api.delete(`/paths/${encodeURIComponent(path)}`);
    return response.data;
  },

  // Alerts
  async getAlerts(limit: number = 100): Promise<AlertResponse[]> {
    const response = await api.get(`/alerts?limit=${limit}`);
    return response.data;
  },

  async exportAlerts(): Promise<{ success: boolean; filename: string; message: string }> {
    const response = await api.get('/alerts/export');
    return response.data;
  },

  // LogFile Analysis
  async analyzeLogFile(file: File): Promise<LogFileAnalysisResponse> {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/logfile/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  async getLogFileInfo(): Promise<LogFileInfoResponse> {
    const response = await api.get('/logfile/info');
    return response.data;
  },

  // API Info
  async getApiInfo(): Promise<{ message: string; version: string }> {
    const response = await api.get('/');
    return response.data;
  },
};
```

### 3. React Hooks

Create `hooks/useWebSocket.ts`:

```typescript
'use client';

import { useEffect, useState } from 'react';
import { wsService, AlertData, StatusData } from '@/lib/websocket';

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [status, setStatus] = useState<StatusData | null>(null);

  useEffect(() => {
    // Connect to WebSocket
    wsService.connect();

    // Set up event handlers
    const handleAlert = (alert: AlertData) => {
      setAlerts(prev => [alert, ...prev.slice(0, 99)]); // Keep last 100 alerts
    };

    const handleStatus = (statusData: StatusData) => {
      setStatus(statusData);
    };

    wsService.onAlert(handleAlert);
    wsService.onStatus(handleStatus);

    // Track connection state
    const checkConnection = () => {
      setIsConnected(wsService['ws']?.readyState === WebSocket.OPEN);
    };

    const interval = setInterval(checkConnection, 1000);

    return () => {
      wsService.removeAlertHandler(handleAlert);
      wsService.removeStatusHandler(handleStatus);
      clearInterval(interval);
      wsService.disconnect();
    };
  }, []);

  return {
    isConnected,
    alerts,
    status,
    clearAlerts: () => setAlerts([]),
  };
}
```

Create `hooks/useMonitoring.ts`:

```typescript
'use client';

import { useState, useEffect } from 'react';
import { apiService } from '@/lib/api';

export function useMonitoring() {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [paths, setPaths] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const status = await apiService.getStatus();
      setIsMonitoring(status.is_monitoring);
      setPaths(status.paths);
      setError(null);
    } catch (err) {
      setError('Failed to load status');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const startMonitoring = async () => {
    try {
      setLoading(true);
      const result = await apiService.startMonitoring();
      if (result.success) {
        setIsMonitoring(true);
        setError(null);
      } else {
        setError(result.message);
      }
    } catch (err) {
      setError('Failed to start monitoring');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const stopMonitoring = async () => {
    try {
      setLoading(true);
      const result = await apiService.stopMonitoring();
      if (result.success) {
        setIsMonitoring(false);
        setError(null);
      } else {
        setError(result.message);
      }
    } catch (err) {
      setError('Failed to stop monitoring');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const addPath = async (path: string) => {
    try {
      setLoading(true);
      const result = await apiService.addPath(path);
      if (result.success) {
        setPaths(result.paths);
        setError(null);
        return true;
      } else {
        setError(result.message);
        return false;
      }
    } catch (err) {
      setError('Failed to add path');
      console.error(err);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const removePath = async (path: string) => {
    try {
      setLoading(true);
      const result = await apiService.removePath(path);
      if (result.success) {
        setPaths(result.paths);
        setError(null);
        return true;
      } else {
        setError(result.message);
        return false;
      }
    } catch (err) {
      setError('Failed to remove path');
      console.error(err);
      return false;
    } finally {
      setLoading(false);
    }
  };

  return {
    isMonitoring,
    paths,
    loading,
    error,
    startMonitoring,
    stopMonitoring,
    addPath,
    removePath,
    refreshStatus: loadStatus,
  };
}
```

## Page Components

### 1. Dashboard Page

Create `app/page.tsx`:

```typescript
'use client';

import { useState } from 'react';
import { useWebSocket, useMonitoring } from '@/hooks';
import { apiService, LogFileAnalysisResponse } from '@/lib/api';
import AlertList from '@/components/AlertList';
import MonitoringControls from '@/components/MonitoringControls';
import StatusCard from '@/components/StatusCard';
import PathManager from '@/components/PathManager';
import LogFileUpload from '@/components/LogFileUpload';
import LogFileResults from '@/components/LogFileResults';

export default function Dashboard() {
  const { isConnected, alerts, clearAlerts } = useWebSocket();
  const { isMonitoring, paths, loading, error, startMonitoring, stopMonitoring, addPath, removePath } = useMonitoring();
  const [logfileResults, setLogFileResults] = useState<LogFileAnalysisResponse | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const handleLogFileAnalysis = (results: LogFileAnalysisResponse) => {
    setLogFileResults(results);
    setUploadError(null);
  };

  const handleLogFileError = (error: string) => {
    setUploadError(error);
    setLogFileResults(null);
  };

  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            🔴 Live Timestomping Monitor
          </h1>
          <div className="flex items-center space-x-4">
            <div className={`flex items-center ${isConnected ? 'text-green-600' : 'text-red-600'}`}>
              <div className={`w-3 h-3 rounded-full mr-2 ${isConnected ? 'bg-green-600' : 'bg-red-600'}`}></div>
              {isConnected ? 'Connected' : 'Disconnected'}
            </div>
            {error && (
              <div className="text-red-600 text-sm">
                Error: {error}
              </div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Controls */}
          <div className="lg:col-span-1 space-y-6">
            <StatusCard 
              isMonitoring={isMonitoring}
              totalAlerts={alerts.length}
              pathsCount={paths.length}
            />
            
            <MonitoringControls
              isMonitoring={isMonitoring}
              loading={loading}
              onStart={startMonitoring}
              onStop={stopMonitoring}
            />
            
            <PathManager
              paths={paths}
              onAddPath={addPath}
              onRemovePath={removePath}
              loading={loading}
            />
          </div>

          {/* Middle Column - LogFile Analysis */}
          <div className="lg:col-span-1 space-y-6">
            <LogFileUpload
              onAnalysisComplete={handleLogFileAnalysis}
              onError={handleLogFileError}
            />
            
            {uploadError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <h3 className="text-red-800 font-medium mb-2">Upload Error</h3>
                <p className="text-red-600 text-sm">{uploadError}</p>
              </div>
            )}
          </div>

          {/* Right Column - Alerts & Results */}
          <div className="lg:col-span-1 space-y-6">
            {logfileResults ? (
              <LogFileResults results={logfileResults} />
            ) : (
              <AlertList 
                alerts={alerts}
                onClearAlerts={clearAlerts}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
```

### 2. Alert List Component

Create `components/AlertList.tsx`:

```typescript
'use client';

import { AlertData } from '@/lib/websocket';

interface AlertListProps {
  alerts: AlertData[];
  onClearAlerts: () => void;
}

export default function AlertList({ alerts, onClearAlerts }: AlertListProps) {
  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getEventTypeIcon = (type: string) => {
    switch (type) {
      case 'modified': return '📝';
      case 'created': return '🆕';
      case 'moved': return '📁';
      case 'timestamp_modified': return '⏰';
      default: return '❓';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold text-gray-900">
          Real-time Alerts ({alerts.length})
        </h2>
        {alerts.length > 0 && (
          <button
            onClick={onClearAlerts}
            className="px-3 py-1 text-sm bg-gray-200 hover:bg-gray-300 rounded-md transition-colors"
          >
            Clear All
          </button>
        )}
      </div>

      {alerts.length === 0 ? (
        <div className="text-center py-8 text-gray-500">
          <div className="text-4xl mb-2">✅</div>
          <p>No alerts detected</p>
        </div>
      ) : (
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {alerts.map((alert) => (
            <div
              key={alert.alert_id}
              className={`border rounded-lg p-4 ${getRiskLevelColor(alert.risk_level)}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center mb-2">
                    <span className="text-lg mr-2">{getEventTypeIcon(alert.event_type)}</span>
                    <span className="font-medium">Alert #{alert.alert_id}</span>
                    <span className={`ml-2 px-2 py-1 text-xs rounded-full ${getRiskLevelColor(alert.risk_level)}`}>
                      {alert.risk_level.toUpperCase()} (Score: {alert.risk_score})
                    </span>
                  </div>
                  
                  <div className="text-sm space-y-1">
                    <div>
                      <span className="font-medium">File:</span> {alert.file_path}
                    </div>
                    <div>
                      <span className="font-medium">Event:</span> {alert.event_type.toUpperCase()}
                    </div>
                    <div>
                      <span className="font-medium">Time:</span> {new Date(alert.timestamp).toLocaleString()}
                    </div>
                    
                    {alert.discrepancies.length > 0 && (
                      <div className="mt-2">
                        <span className="font-medium">Discrepancies:</span>
                        <ul className="ml-4 mt-1 list-disc text-sm">
                          {alert.discrepancies.map((discrepancy, index) => (
                            <li key={index}>{discrepancy}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

### 3. Status Card Component

Create `components/StatusCard.tsx`:

```typescript
'use client';

interface StatusCardProps {
  isMonitoring: boolean;
  totalAlerts: number;
  pathsCount: number;
}

export default function StatusCard({ isMonitoring, totalAlerts, pathsCount }: StatusCardProps) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Status</h2>
      
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-gray-600">Monitoring Status</span>
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${
            isMonitoring 
              ? 'bg-green-100 text-green-800' 
              : 'bg-gray-100 text-gray-800'
          }`}>
            {isMonitoring ? '🔴 Active' : '⏸️ Inactive'}
          </span>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-gray-600">Total Alerts</span>
          <span className="font-semibold">{totalAlerts}</span>
        </div>
        
        <div className="flex items-center justify-between">
          <span className="text-gray-600">Monitored Paths</span>
          <span className="font-semibold">{pathsCount}</span>
        </div>
      </div>
    </div>
  );
}
```

### 4. Monitoring Controls Component

Create `components/MonitoringControls.tsx`:

```typescript
'use client';

interface MonitoringControlsProps {
  isMonitoring: boolean;
  loading: boolean;
  onStart: () => void;
  onStop: () => void;
}

export default function MonitoringControls({ isMonitoring, loading, onStart, onStop }: MonitoringControlsProps) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Monitoring Controls</h2>
      
      <div className="space-y-3">
        {!isMonitoring ? (
          <button
            onClick={onStart}
            disabled={loading}
            className="w-full px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Starting...' : '🔴 Start Monitoring'}
          </button>
        ) : (
          <button
            onClick={onStop}
            disabled={loading}
            className="w-full px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Stopping...' : '⏹️ Stop Monitoring'}
          </button>
        )}
      </div>
    </div>
  );
}
```

### 5. Path Manager Component

Create `components/PathManager.tsx`:

```typescript
'use client';

import { useState } from 'react';

interface PathManagerProps {
  paths: string[];
  onAddPath: (path: string) => Promise<boolean>;
  onRemovePath: (path: string) => Promise<boolean>;
  loading: boolean;
}

export default function PathManager({ paths, onAddPath, onRemovePath, loading }: PathManagerProps) {
  const [newPath, setNewPath] = useState('');

  const handleAddPath = async () => {
    if (newPath.trim()) {
      const success = await onAddPath(newPath.trim());
      if (success) {
        setNewPath('');
      }
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleAddPath();
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Monitored Paths</h2>
      
      {/* Add Path */}
      <div className="flex gap-2 mb-4">
        <input
          type="text"
          value={newPath}
          onChange={(e) => setNewPath(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Enter path to monitor..."
          className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          disabled={loading}
        />
        <button
          onClick={handleAddPath}
          disabled={loading || !newPath.trim()}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          Add
        </button>
      </div>

      {/* Path List */}
      <div className="space-y-2 max-h-48 overflow-y-auto">
        {paths.length === 0 ? (
          <p className="text-gray-500 text-sm">No paths configured</p>
        ) : (
          paths.map((path, index) => (
            <div
              key={index}
              className="flex items-center justify-between p-2 bg-gray-50 rounded-md"
            >
              <span className="text-sm truncate flex-1">{path}</span>
              <button
                onClick={() => onRemovePath(path)}
                disabled={loading}
                className="ml-2 px-2 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Remove
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
```

### 6. LogFile Upload Component

Create `components/LogFileUpload.tsx`:

```typescript
'use client';

import { useState, useRef } from 'react';
import { apiService, LogFileAnalysisResponse } from '@/lib/api';

interface LogFileUploadProps {
  onAnalysisComplete?: (results: LogFileAnalysisResponse) => void;
  onError?: (error: string) => void;
}

export default function LogFileUpload({ onAnalysisComplete, onError }: LogFileUploadProps) {
  const [uploading, setUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (file: File) => {
    if (!file) return;

    // Validate file size (max 100MB)
    if (file.size > 100 * 1024 * 1024) {
      onError?.('File size must be less than 100MB');
      return;
    }

    setUploading(true);
    
    try {
      const results = await apiService.analyzeLogFile(file);
      onAnalysisComplete?.(results);
    } catch (error: any) {
      const errorMessage = error.response?.data?.detail || error.message || 'Upload failed';
      onError?.(errorMessage);
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const openFileDialog = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">$LogFile Analysis</h2>
      
      <div
        className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
          dragActive
            ? 'border-blue-400 bg-blue-50'
            : 'border-gray-300 hover:border-gray-400'
        } ${uploading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={!uploading ? openFileDialog : undefined}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".bin,.logfile"
          onChange={handleFileSelect}
          className="hidden"
          disabled={uploading}
        />
        
        {uploading ? (
          <div className="space-y-2">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="text-gray-600">Analyzing $LogFile...</p>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="text-4xl">📁</div>
            <p className="text-lg font-medium text-gray-900">
              Drop $LogFile here or click to browse
            </p>
            <p className="text-sm text-gray-500">
              Supports .bin and .logfile files (max 100MB)
            </p>
            <p className="text-xs text-gray-400 mt-2">
              Extract $LogFile using: icat -o &lt;offset&gt; &lt;image&gt; 2 &gt; logfile.bin
            </p>
          </div>
        )}
      </div>
      
      <div className="mt-4 text-sm text-gray-600">
        <p className="font-medium mb-2">What this detects:</p>
        <ul className="list-disc list-inside space-y-1 text-xs">
          <li>Timestamp tampering evidence from $LogFile operations</li>
          <li>Anti-forensics tool usage (timestomp.exe, etc.)</li>
          <li>Rapid timestamp changes indicating manipulation</li>
          <li>Impossible timestamp sequences</li>
          <li>SetNewAttributeValue (0x05) operations</li>
          <li>UpdateResidentValue (0x07) operations</li>
        </ul>
      </div>
    </div>
  );
}
```

### 7. LogFile Results Component

Create `components/LogFileResults.tsx`:

```typescript
'use client';

import { LogFileAnalysisResponse } from '@/lib/api';

interface LogFileResultsProps {
  results: LogFileAnalysisResponse | null;
}

export default function LogFileResults({ results }: LogFileResultsProps) {
  if (!results) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Analysis Results</h2>
        <div className="text-center py-8 text-gray-500">
          <div className="text-4xl mb-2">📊</div>
          <p>Upload a $LogFile to see analysis results</p>
        </div>
      </div>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Analysis Results</h2>
      
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-blue-600">{results.total_pages}</div>
          <div className="text-sm text-blue-800">Total Pages</div>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-green-600">{results.total_records}</div>
          <div className="text-sm text-green-800">Total Records</div>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-purple-600">{results.inode_count}</div>
          <div className="text-sm text-purple-800">Inodes Modified</div>
        </div>
        <div className="bg-orange-50 p-4 rounded-lg">
          <div className="text-2xl font-bold text-orange-600">{results.tampering_evidence_count}</div>
          <div className="text-sm text-orange-800">Evidence Found</div>
        </div>
      </div>

      {/* High Risk Indicators */}
      {results.high_risk_indicators_count > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-semibold text-red-600 mb-3">
            🚨 High Risk Indicators ({results.high_risk_indicators_count})
          </h3>
          <div className="space-y-3">
            {results.high_risk_indicators.map((evidence, index) => (
              <div
                key={index}
                className={`border rounded-lg p-4 ${getSeverityColor(evidence.severity)}`}
              >
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-medium">{evidence.description}</h4>
                  <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(evidence.severity)}`}>
                    {evidence.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-sm space-y-1">
                  <div><strong>Type:</strong> {evidence.type}</div>
                  <div><strong>Inode:</strong> {evidence.inode}</div>
                  {evidence.time_difference && (
                    <div><strong>Time Difference:</strong> {evidence.time_difference.seconds}s</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Evidence */}
      {results.tampering_evidence.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-gray-900 mb-3">
            🔍 All Evidence ({results.tampering_evidence.length})
          </h3>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {results.tampering_evidence.map((evidence, index) => (
              <div
                key={index}
                className={`border rounded-lg p-3 ${getSeverityColor(evidence.severity)}`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{evidence.description}</span>
                  <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(evidence.severity)}`}>
                    {evidence.severity}
                  </span>
                </div>
                <div className="text-xs mt-1">
                  Inode: {evidence.inode} | Type: {evidence.type}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Evidence */}
      {results.tampering_evidence_count === 0 && (
        <div className="text-center py-8 text-green-600">
          <div className="text-4xl mb-2">✅</div>
          <p className="font-medium">No timestamp tampering evidence detected</p>
          <p className="text-sm text-gray-500 mt-1">
            The $LogFile appears clean based on the analysis
          </p>
        </div>
      )}
    </div>
  );
}
```

## Styling

### Tailwind CSS Configuration

Update `tailwind.config.ts`:

```typescript
import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
        }
      }
    },
  },
  plugins: [],
}
export default config
```

## Running the Application

### 1. Start the Backend

```bash
python live_monitor_api.py
```

### 2. Start the Frontend

```bash
npm run dev
# or
yarn dev
```

### 3. Access the Application

Open `http://localhost:3000` in your browser.

## Features Implemented

- **Real-time Alerts**: Live updates via WebSocket
- **Monitoring Control**: Start/stop monitoring
- **Path Management**: Add/remove monitoring paths
- **Status Display**: Connection status and statistics
- **Alert History**: View and clear alerts
- **Responsive Design**: Works on desktop and mobile
- **Error Handling**: Proper error states and messages
- **Loading States**: Visual feedback during operations

## Additional Features to Consider

1. **Alert Filtering**: Filter alerts by risk level, file type, or time range
2. **Export Functionality**: Download alerts as CSV or JSON
3. **Settings Panel**: Configure thresholds and monitoring options
4. **Dark Mode**: Toggle between light and dark themes
5. **Notifications**: Browser notifications for high-risk alerts
6. **Charts/Graphs**: Visual representation of alert trends
7. **File Details**: Detailed view of file analysis results
8. **Search**: Search through alerts and file paths

## Troubleshooting

### Common Issues

1. **WebSocket Connection Fails**
   - Ensure backend is running on `localhost:8000`
   - Check CORS configuration in backend
   - Verify firewall settings

2. **API Calls Fail**
   - Check backend server status
   - Verify API endpoints are accessible
   - Check network connectivity

3. **Real-time Updates Not Working**
   - Ensure WebSocket connection is established
   - Check browser console for errors
   - Verify event handlers are properly registered

### Debug Mode

Enable debug logging in the browser console:

```typescript
// In lib/websocket.ts
this.ws.onmessage = (event) => {
  console.log('WebSocket message received:', event.data);
  // ... rest of handler
};
```

## Security Considerations

1. **Authentication**: Implement JWT or session-based auth
2. **Authorization**: Role-based access control
3. **Input Validation**: Validate all user inputs
4. **Rate Limiting**: Prevent API abuse
5. **HTTPS**: Use secure connections in production
