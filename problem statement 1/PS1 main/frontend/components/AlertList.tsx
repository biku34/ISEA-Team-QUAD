'use client';

import { Button } from '@/components/ui/button';
import type { AlertData } from '@/lib/api';

interface AlertListProps {
  alerts: AlertData[];
  onClearAlerts: () => void;
}

export function AlertList({ alerts, onClearAlerts }: AlertListProps) {
  const getRiskLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'high':
        return 'bg-red-50 border-red-200 text-red-900';
      case 'medium':
        return 'bg-yellow-50 border-yellow-200 text-yellow-900';
      default:
        return 'bg-blue-50 border-blue-200 text-blue-900';
    }
  };

  const getRiskBadgeColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'high':
        return 'bg-red-100 text-red-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-blue-100 text-blue-800';
    }
  };

  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="font-semibold text-lg">
          Alerts ({alerts.length})
        </h2>
        {alerts.length > 0 && (
          <Button
            onClick={onClearAlerts}
            variant="outline"
            size="sm"
          >
            Clear All
          </Button>
        )}
      </div>

      {alerts.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          <div className="text-3xl mb-2">✓</div>
          <p>No alerts detected</p>
        </div>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {alerts.map((alert) => (
            <div
              key={alert.alert_id}
              className={`border rounded-lg p-3 text-sm ${getRiskLevelColor(
                alert.risk_level
              )}`}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="font-semibold">Alert #{alert.alert_id}</div>
                <span
                  className={`px-2 py-1 rounded text-xs font-medium ${getRiskBadgeColor(
                    alert.risk_level
                  )}`}
                >
                  {alert.risk_level.toUpperCase()} ({alert.risk_score})
                </span>
              </div>

              <div className="space-y-1 text-xs">
                <div>
                  <span className="font-medium">File:</span> {alert.file_path}
                </div>
                <div>
                  <span className="font-medium">Event:</span> {alert.event_type}
                </div>
                <div>
                  <span className="font-medium">Time:</span>{' '}
                  {new Date(alert.timestamp).toLocaleString()}
                </div>

                {alert.discrepancies.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-current/20">
                    <div className="font-medium mb-1">Discrepancies:</div>
                    <ul className="list-disc list-inside space-y-0.5">
                      {alert.discrepancies.map((disc, idx) => (
                        <li key={idx}>{disc}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
