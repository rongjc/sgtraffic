import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Upload, CheckCircle, XCircle, AlertTriangle, Clock, Loader2, BarChart2, GitCompare, Layers } from 'lucide-react';
import { listScans, type Scan } from '../api';

function VerdictChip({ verdict }: { verdict: Scan['verdict'] }) {
  const map = {
    clean:      { label: 'Clean',      cls: 'bg-green-900/50 text-green-300',   Icon: CheckCircle },
    pha:        { label: 'Malware',    cls: 'bg-red-900/50 text-red-300',       Icon: XCircle },
    suspicious: { label: 'Suspicious', cls: 'bg-yellow-900/50 text-yellow-300', Icon: AlertTriangle },
    unknown:    { label: 'Pending',    cls: 'bg-gray-800 text-gray-400',        Icon: Clock },
  };
  const { label, cls, Icon } = map[verdict];
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium ${cls}`}>
      <Icon className="w-3 h-3" /> {label}
    </span>
  );
}

function StatusDot({ status }: { status: Scan['status'] }) {
  const map = {
    pending:   'bg-gray-500',
    analyzing: 'bg-indigo-400 animate-pulse',
    done:      'bg-green-500',
    error:     'bg-red-500',
  };
  return <span className={`inline-block w-2 h-2 rounded-full ${map[status]}`} />;
}

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listScans()
      .then(data => setScans([...data].reverse()))
      .catch(() => setError('Failed to load scan history.'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen px-4 py-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-indigo-400" />
          <h1 className="text-2xl font-bold">Scan History</h1>
        </div>
        <div className="flex gap-3 flex-wrap">
          <Link
            to="/apps"
            className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            <Layers className="w-4 h-4" /> Portfolio
          </Link>
          <Link
            to="/compare"
            className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            <GitCompare className="w-4 h-4" /> Compare
          </Link>
          <Link
            to="/metrics"
            className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            <BarChart2 className="w-4 h-4" /> Analytics
          </Link>
          <Link
            to="/"
            className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            <Upload className="w-4 h-4" /> New Scan
          </Link>
        </div>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20 gap-2 text-gray-400">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading…
        </div>
      )}

      {error && (
        <div className="bg-red-950 border border-red-700 rounded-xl p-4 text-red-300 text-sm">{error}</div>
      )}

      {!loading && !error && scans.length === 0 && (
        <div className="text-center py-20 text-gray-500">
          <Shield className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium mb-2">No scans yet</p>
          <p className="text-sm">Upload an APK to get started.</p>
        </div>
      )}

      {!loading && scans.length > 0 && (
        <div className="bg-gray-900 rounded-xl overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_auto_auto_auto] gap-4 px-5 py-3 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
            <span>Filename</span>
            <span className="text-right">Date</span>
            <span className="text-right">Verdict</span>
            <span className="text-right">Risk</span>
          </div>
          {/* Rows */}
          <div className="divide-y divide-gray-800">
            {scans.map(scan => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="grid grid-cols-[1fr_auto_auto_auto] gap-4 px-5 py-4 hover:bg-gray-800/60 transition-colors items-center"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <StatusDot status={scan.status} />
                  <span className="text-sm text-gray-200 truncate font-medium">{scan.filename}</span>
                </div>
                <span className="text-xs text-gray-500 whitespace-nowrap text-right">
                  {new Date(scan.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                </span>
                <div className="flex justify-end">
                  <VerdictChip verdict={scan.verdict} />
                </div>
                <span className="text-sm text-right font-mono w-8">
                  {scan.riskScore !== null ? (
                    <span className={scan.riskScore >= 75 ? 'text-red-400' : scan.riskScore >= 40 ? 'text-yellow-400' : 'text-green-400'}>
                      {scan.riskScore}
                    </span>
                  ) : (
                    <span className="text-gray-600">—</span>
                  )}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
