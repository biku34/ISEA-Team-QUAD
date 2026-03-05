const API_BASE_URL = 'http://localhost:8080';

export interface AlertData {
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

interface MonitoringStatusResponse {
  is_monitoring: boolean;
  paths: string[];
  total_alerts: number;
  recent_alerts: AlertData[];
}

const handleResponse = async (response: Response) => {
  if (!response.ok) {
    throw new Error(`API error: ${response.statusText}`);
  }
  return response.json();
};

export const apiService = {
  async getStatus(): Promise<MonitoringStatusResponse> {
    const response = await fetch(`${API_BASE_URL}/status`);
    return handleResponse(response);
  },

  async startMonitoring(): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${API_BASE_URL}/monitoring/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    return handleResponse(response);
  },

  async stopMonitoring(): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${API_BASE_URL}/monitoring/stop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    return handleResponse(response);
  },

  async getAlerts(limit: number = 50): Promise<AlertData[]> {
    const response = await fetch(`${API_BASE_URL}/alerts?limit=${limit}`);
    return handleResponse(response);
  },

  async exportAlerts(): Promise<{ success: boolean; filename: string; message: string }> {
    const response = await fetch(`${API_BASE_URL}/alerts/export`);
    return handleResponse(response);
  },

  async getPaths(): Promise<string[]> {
    const response = await fetch(`${API_BASE_URL}/paths`);
    return handleResponse(response);
  },

  async addPath(path: string): Promise<{ success: boolean; message: string; paths: string[] }> {
    const response = await fetch(`${API_BASE_URL}/paths/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    return handleResponse(response);
  },

  async removePath(path: string): Promise<{ success: boolean; message: string; paths: string[] }> {
    const encodedPath = encodeURIComponent(path);
    const response = await fetch(`${API_BASE_URL}/paths/${encodedPath}`, {
      method: 'DELETE',
    });
    return handleResponse(response);
  },

  async analyzeLogFile(file: File): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch(`${API_BASE_URL}/logfile/analyze`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse(response);
  },

  async getLogFileInfo(): Promise<any> {
    const response = await fetch(`${API_BASE_URL}/logfile/info`);
    return handleResponse(response);
  },
};
