'use client';

import { useEffect, useState } from 'react';
import { wsService, AlertData, StatusData } from '@/lib/websocket';

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [status, setStatus] = useState<StatusData | null>(null);

  useEffect(() => {
    wsService.connect();

    const handleAlert = (alert: AlertData) => {
      setAlerts(prev => [alert, ...prev.slice(0, 99)]);
    };

    const handleStatus = (statusData: StatusData) => {
      setStatus(statusData);
    };

    wsService.onAlert(handleAlert);
    wsService.onStatus(handleStatus);

    const checkConnection = () => {
      const isOpen = (wsService as any).ws?.readyState === WebSocket.OPEN;
      setIsConnected(isOpen);
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
