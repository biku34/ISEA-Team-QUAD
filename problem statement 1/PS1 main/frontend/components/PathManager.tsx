'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { apiService } from '@/lib/api';
import { Trash2, Plus } from 'lucide-react';

export function PathManager() {
  const [paths, setPaths] = useState<string[]>([]);
  const [newPath, setNewPath] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadPaths();
  }, []);

  const loadPaths = async () => {
    try {
      const loadedPaths = await apiService.getPaths();
      setPaths(loadedPaths);
    } catch (err) {
      setError('Failed to load paths');
      console.error(err);
    }
  };

  const handleAddPath = async () => {
    if (!newPath.trim()) return;

    setLoading(true);
    setError('');
    try {
      const result = await apiService.addPath(newPath);
      setPaths(result.paths);
      setNewPath('');
    } catch (err) {
      setError('Failed to add path');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRemovePath = async (path: string) => {
    setLoading(true);
    setError('');
    try {
      const result = await apiService.removePath(path);
      setPaths(result.paths);
    } catch (err) {
      setError('Failed to remove path');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm p-6">
      <h2 className="font-semibold text-lg mb-4">Monitored Paths</h2>

      <div className="space-y-4">
        <div className="flex gap-2">
          <Input
            placeholder="Enter path (e.g. C:\\Windows\\System32)"
            value={newPath}
            onChange={(e) => setNewPath(e.target.value)}
            disabled={loading}
            onKeyPress={(e) => e.key === 'Enter' && handleAddPath()}
            className="text-sm"
          />
          <Button
            onClick={handleAddPath}
            disabled={loading || !newPath.trim()}
            size="sm"
            className="gap-2"
          >
            <Plus size={16} />
            Add
          </Button>
        </div>

        {error && (
          <div className="p-2 bg-red-50 text-red-800 rounded text-xs">
            {error}
          </div>
        )}

        <div className="space-y-2 max-h-48 overflow-y-auto">
          {paths.length === 0 ? (
            <div className="text-center py-6 text-muted-foreground text-sm">
              No paths configured
            </div>
          ) : (
            paths.map((path) => (
              <div
                key={path}
                className="flex items-center justify-between gap-2 p-2 rounded border border-border bg-muted/50 text-sm"
              >
                <code className="text-xs flex-1 truncate">{path}</code>
                <Button
                  onClick={() => handleRemovePath(path)}
                  disabled={loading}
                  variant="ghost"
                  size="sm"
                  className="h-7 w-7 p-0"
                >
                  <Trash2 size={14} />
                </Button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
