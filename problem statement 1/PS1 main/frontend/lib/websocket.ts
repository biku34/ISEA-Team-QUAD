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

export interface LogFileAlertData {
  message: string;
  evidence_count: number;
  filename: string;
  analysis_time: string;
}

interface WebSocketMessage {
  type: 'alert' | 'status' | 'pong' | 'logfile_alert';
  data?: AlertData | StatusData | LogFileAlertData;
}

type AlertHandler = (alert: AlertData) => void;
type StatusHandler = (status: StatusData) => void;
type LogFileAlertHandler = (alert: LogFileAlertData) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private alertHandlers: AlertHandler[] = [];
  private statusHandlers: StatusHandler[] = [];
  private logFileAlertHandlers: LogFileAlertHandler[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private pingInterval: NodeJS.Timeout | null = null;

  connect(url: string = 'ws://localhost:8080/ws') {
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
          case 'logfile_alert':
            this.logFileAlertHandlers.forEach(handler => handler(message.data as LogFileAlertData));
            break;
          case 'pong':
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
    }, 30000);
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

  onLogFileAlert(handler: LogFileAlertHandler) {
    this.logFileAlertHandlers.push(handler);
  }

  removeLogFileAlertHandler(handler: LogFileAlertHandler) {
    const index = this.logFileAlertHandlers.indexOf(handler);
    if (index > -1) {
      this.logFileAlertHandlers.splice(index, 1);
    }
  }
}

export const wsService = new WebSocketService();
export type { AlertData, StatusData, LogFileAlertData };
