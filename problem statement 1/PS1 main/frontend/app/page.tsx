'use client';

import { useWebSocket } from '@/hooks/useWebSocket';
import { useMonitoring } from '@/hooks/useMonitoring';
import { StatusCard } from '@/components/StatusCard';
import { MonitoringControls } from '@/components/MonitoringControls';
import { AlertList } from '@/components/AlertList';
import { PathManager } from '@/components/PathManager';
import { LogFileAnalyzer } from '@/components/LogFileAnalyzer';
import { ExportAlerts } from '@/components/ExportAlerts';

export default function Dashboard() {
  const { isConnected, alerts, clearAlerts } = useWebSocket();
  const {
    isMonitoring,
    loading,
    error,
    startMonitoring,
    stopMonitoring,
  } = useMonitoring();

  return (
    <main className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card shadow-sm">
        <div className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold tracking-tight">
                Timestomp Monitor
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                Real-time file monitoring and NTFS analysis
              </p>
            </div>
            <div className="flex items-center gap-3">
              <div
                className={`flex items-center gap-2 px-3 py-2 rounded-lg ${
                  isConnected ? 'bg-green-50' : 'bg-red-50'
                }`}
              >
                <div
                  className={`w-2 h-2 rounded-full ${
                    isConnected ? 'bg-green-500' : 'bg-red-500'
                  }`}
                />
                <span className="text-xs font-medium">
                  {isConnected ? 'Connected' : 'Disconnected'}
                </span>
              </div>
            </div>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-red-50 text-red-800 rounded-lg text-sm">
              {error}
            </div>
          )}
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-6">
            <StatusCard
              isMonitoring={isMonitoring}
              isConnected={isConnected}
              totalAlerts={alerts.length}
            />

            <MonitoringControls
              isMonitoring={isMonitoring}
              loading={loading}
              onStart={startMonitoring}
              onStop={stopMonitoring}
            />

            <div className="rounded-lg border bg-card text-card-foreground shadow-sm p-6">
              <h2 className="font-semibold text-lg mb-4">Quick Actions</h2>
              <ExportAlerts alertCount={alerts.length} />
            </div>

            <PathManager />

            <LogFileAnalyzer />
          </div>

          {/* Main Content */}
          <div className="lg:col-span-2">
            <AlertList alerts={alerts} onClearAlerts={clearAlerts} />
          </div>
        </div>
      </div>
    </main>
  );
}
