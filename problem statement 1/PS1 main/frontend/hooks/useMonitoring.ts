'use client';

import { useState, useEffect } from 'react';
import { apiService } from '@/lib/api';

export function useMonitoring() {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [totalAlerts, setTotalAlerts] = useState(0);
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
      setTotalAlerts(status.total_alerts);
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

  return {
    isMonitoring,
    totalAlerts,
    loading,
    error,
    startMonitoring,
    stopMonitoring,
    refreshStatus: loadStatus,
  };
}
