'use client';

import { Button } from '@/components/ui/button';

interface MonitoringControlsProps {
  isMonitoring: boolean;
  loading: boolean;
  onStart: () => void;
  onStop: () => void;
}

export function MonitoringControls({
  isMonitoring,
  loading,
  onStart,
  onStop,
}: MonitoringControlsProps) {
  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm p-6">
      <h2 className="font-semibold text-lg mb-4">Controls</h2>

      {!isMonitoring ? (
        <Button
          onClick={onStart}
          disabled={loading}
          className="w-full bg-green-600 hover:bg-green-700"
        >
          {loading ? 'Starting...' : 'Start Monitoring'}
        </Button>
      ) : (
        <Button
          onClick={onStop}
          disabled={loading}
          variant="destructive"
          className="w-full"
        >
          {loading ? 'Stopping...' : 'Stop Monitoring'}
        </Button>
      )}
    </div>
  );
}
