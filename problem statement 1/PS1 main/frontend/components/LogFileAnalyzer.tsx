'use client';

import { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { apiService } from '@/lib/api';
import { Upload, AlertCircle } from 'lucide-react';

interface AnalysisResult {
  success: boolean;
  message: string;
  total_pages: number;
  total_records: number;
  inode_count: number;
  tampering_evidence_count: number;
  high_risk_indicators_count: number;
}

export function LogFileAnalyzer() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const analysisResult = await apiService.analyzeLogFile(file);
      setResult(analysisResult);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to analyze LogFile'
      );
      console.error(err);
    } finally {
      setLoading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm p-6">
      <h2 className="font-semibold text-lg mb-4">$LogFile Analysis</h2>

      <div className="space-y-4">
        <div
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-border rounded-lg p-6 text-center cursor-pointer hover:bg-muted/50 transition"
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileSelect}
            disabled={loading}
            accept=".bin,.logfile"
            className="hidden"
          />
          <Upload className="mx-auto mb-2 text-muted-foreground" size={24} />
          <p className="text-sm font-medium">Click to upload $LogFile</p>
          <p className="text-xs text-muted-foreground mt-1">
            Maximum 100MB
          </p>
        </div>

        {loading && (
          <div className="p-3 bg-blue-50 text-blue-800 rounded text-sm flex items-center gap-2">
            <div className="w-4 h-4 border-2 border-blue-300 border-t-blue-800 rounded-full animate-spin" />
            Analyzing LogFile...
          </div>
        )}

        {error && (
          <div className="p-3 bg-red-50 text-red-800 rounded text-sm flex items-center gap-2">
            <AlertCircle size={16} />
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-3 p-4 bg-muted/30 rounded-lg">
            <div className="font-medium text-sm mb-3">{result.message}</div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-2 bg-background rounded border border-border">
                <div className="text-xs text-muted-foreground">Pages</div>
                <div className="font-semibold text-lg">
                  {result.total_pages}
                </div>
              </div>

              <div className="p-2 bg-background rounded border border-border">
                <div className="text-xs text-muted-foreground">Records</div>
                <div className="font-semibold text-lg">
                  {result.total_records}
                </div>
              </div>

              <div className="p-2 bg-background rounded border border-border">
                <div className="text-xs text-muted-foreground">Inodes</div>
                <div className="font-semibold text-lg">
                  {result.inode_count}
                </div>
              </div>

              <div className="p-2 bg-background rounded border border-red-200 bg-red-50">
                <div className="text-xs text-red-700">Tampering Evidence</div>
                <div className="font-semibold text-lg text-red-700">
                  {result.tampering_evidence_count}
                </div>
              </div>
            </div>

            {result.high_risk_indicators_count > 0 && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-800">
                <div className="font-medium flex items-center gap-2 mb-1">
                  <AlertCircle size={16} />
                  High Risk Indicators
                </div>
                <div>
                  {result.high_risk_indicators_count} high-risk indicator
                  {result.high_risk_indicators_count !== 1 ? 's' : ''} detected
                </div>
              </div>
            )}
          </div>
        )}

        <Button
          onClick={() => fileInputRef.current?.click()}
          disabled={loading}
          variant="outline"
          className="w-full"
        >
          {result ? 'Analyze Another File' : 'Select File'}
        </Button>
      </div>
    </div>
  );
}
