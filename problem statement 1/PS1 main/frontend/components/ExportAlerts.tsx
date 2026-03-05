'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { apiService } from '@/lib/api';
import { Download, CheckCircle } from 'lucide-react';

export function ExportAlerts({ alertCount }: { alertCount: number }) {
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleExport = async () => {
    setLoading(true);
    setSuccess(false);

    try {
      const result = await apiService.exportAlerts();
      if (result.success) {
        setSuccess(true);
        setTimeout(() => setSuccess(false), 3000);
      }
    } catch (err) {
      console.error('Failed to export alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <Button
        onClick={handleExport}
        disabled={loading || alertCount === 0}
        className="w-full gap-2"
      >
        <Download size={16} />
        {loading ? 'Exporting...' : 'Export Alerts'}
      </Button>

      {success && (
        <div className="p-2 bg-green-50 text-green-800 rounded text-xs flex items-center gap-2">
          <CheckCircle size={14} />
          Alerts exported successfully
        </div>
      )}
    </div>
  );
}
