import axios from 'axios';

const api = axios.create({ baseURL: '/api' });

export interface Scan {
  id: string;
  filename: string;
  fileHashSha256: string;
  status: 'pending' | 'analyzing' | 'done' | 'error';
  verdict: 'clean' | 'pha' | 'suspicious' | 'unknown';
  phaCategories: string[];
  riskScore: number | null;
  errorMessage: string | null;
  createdAt: string;
  completedAt: string | null;
  privacyScore?: number | null;
  trackersDetected?: string[] | null;
}

export interface Finding {
  id: string;
  scanId: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  rule: string;
  description: string;
  evidence: string | null;
}

export async function uploadApk(file: File, onProgress: (pct: number) => void): Promise<{ id: string }> {
  const form = new FormData();
  form.append('file', file);
  const { data } = await api.post<{ id: string }>('/scans', form, {
    onUploadProgress: (e) => {
      if (e.total) onProgress(Math.round((e.loaded / e.total) * 100));
    },
  });
  return data;
}

export async function getScan(id: string): Promise<Scan> {
  const { data } = await api.get<Scan>(`/scans/${id}`);
  return data;
}

export async function listScans(): Promise<Scan[]> {
  const { data } = await api.get<Scan[]>('/scans');
  return data;
}

export async function getFindings(id: string): Promise<Finding[]> {
  const { data } = await api.get<Finding[]>(`/scans/${id}/findings`);
  return data;
}

export interface Metrics {
  overview: {
    totalScans: number;
    scansToday: number;
    scansThisWeek: number;
    scansThisMonth: number;
    errorRate: number;
    avgScanTimeMs: number | null;
    avgRiskScore: number | null;
  };
  verdictBreakdown: Record<string, number>;
  detectionRate: number;
  scanVolumeByDay: { date: string; count: number }[];
  topPhaCategories: { category: string; count: number }[];
  findingsBySeverity: Record<string, number>;
  topRules: { rule: string; count: number }[];
  userActivity: { user_id: string | null; scan_count: number }[];
  riskScoreDistribution: { low: number; moderate: number; high: number; critical: number };
  trackerPrevalence: { tracker: string; count: number }[];
  privacyScoreDistribution: { low: number; moderate: number; high: number; critical: number; avgScore: number | null };
}

export async function getMetrics(): Promise<Metrics> {
  const { data } = await api.get<Metrics>('/metrics');
  return data;
}

export async function downloadReport(id: string): Promise<void> {
  const response = await api.get(`/scans/${id}/report`, { responseType: 'blob' });
  const url = URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan-report-${id}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}
