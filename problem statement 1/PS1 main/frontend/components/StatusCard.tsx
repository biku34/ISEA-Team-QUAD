'use client';

interface StatusCardProps {
  isMonitoring: boolean;
  isConnected: boolean;
  totalAlerts: number;
}

export function StatusCard({ isMonitoring, isConnected, totalAlerts }: StatusCardProps) {
  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm p-6">
      <h2 className="font-semibold text-lg mb-4">Status</h2>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Connection</span>
          <div className="flex items-center gap-2">
            <div
              className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-green-500' : 'bg-red-500'
              }`}
            />
            <span className="text-sm font-medium">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Monitoring</span>
          <span
            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
              isMonitoring
                ? 'bg-green-100 text-green-800'
                : 'bg-gray-100 text-gray-800'
            }`}
          >
            {isMonitoring ? 'Active' : 'Inactive'}
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Total Alerts</span>
          <span className="text-sm font-semibold">{totalAlerts}</span>
        </div>
      </div>
    </div>
  );
}
