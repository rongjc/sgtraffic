import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Shield, AlertTriangle, CheckCircle, XCircle,
  ChevronDown, ChevronUp, ArrowLeft, Clock, Loader2, FileDown,
} from 'lucide-react';
import { getScan, getFindings, downloadReport, type Scan, type Finding } from '../api';

const POLL_INTERVAL = 3000;

const SEVERITY_ORDER: Finding['severity'][] = ['critical', 'high', 'medium', 'low'];

const SEVERITY_STYLES: Record<Finding['severity'], string> = {
  critical: 'bg-red-900/50 border-red-700 text-red-300',
  high:     'bg-orange-900/50 border-orange-700 text-orange-300',
  medium:   'bg-yellow-900/50 border-yellow-700 text-yellow-300',
  low:      'bg-gray-800 border-gray-700 text-gray-400',
};

const SEVERITY_BADGE: Record<Finding['severity'], string> = {
  critical: 'bg-red-800 text-red-200',
  high:     'bg-orange-800 text-orange-200',
  medium:   'bg-yellow-800 text-yellow-200',
  low:      'bg-gray-700 text-gray-300',
};

function VerdictBadge({ verdict }: { verdict: Scan['verdict'] }) {
  const map = {
    clean:      { label: 'CLEAN',     cls: 'bg-green-800 text-green-200', Icon: CheckCircle },
    pha:        { label: 'MALWARE',   cls: 'bg-red-800 text-red-200',     Icon: XCircle },
    suspicious: { label: 'SUSPICIOUS',cls: 'bg-yellow-800 text-yellow-200', Icon: AlertTriangle },
    unknown:    { label: 'UNKNOWN',   cls: 'bg-gray-700 text-gray-300',   Icon: Clock },
  };
  const { label, cls, Icon } = map[verdict];
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold ${cls}`}>
      <Icon className="w-4 h-4" /> {label}
    </span>
  );
}

function RiskMeter({ score }: { score: number }) {
  const color = score >= 75 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500';
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 bg-gray-800 rounded-full h-3">
        <div className={`h-3 rounded-full transition-all duration-500 ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-lg font-bold w-10 text-right">{score}</span>
    </div>
  );
}

function FindingGroup({ severity, findings }: { severity: Finding['severity']; findings: Finding[] }) {
  const [open, setOpen] = useState(true);
  if (!findings.length) return null;
  return (
    <div className={`rounded-xl border ${SEVERITY_STYLES[severity]} mb-4`}>
      <button
        className="w-full flex items-center justify-between px-4 py-3 font-semibold capitalize"
        onClick={() => setOpen(o => !o)}
      >
        <span className="flex items-center gap-2">
          <span className={`text-xs px-2 py-0.5 rounded-full font-bold uppercase ${SEVERITY_BADGE[severity]}`}>
            {severity}
          </span>
          {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>
        {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
      </button>
      {open && (
        <div className="divide-y divide-gray-700/50">
          {findings.map(f => (
            <div key={f.id} className="px-4 py-3">
              <div className="flex items-start justify-between gap-2 mb-1">
                <span className="font-medium text-sm">{f.rule}</span>
                <span className="text-xs text-gray-500 shrink-0">{f.category}</span>
              </div>
              <p className="text-sm text-gray-300 mb-2">{f.description}</p>
              {f.evidence && (
                <pre className="text-xs bg-gray-950 rounded p-2 overflow-x-auto text-gray-400 whitespace-pre-wrap break-words">
                  {f.evidence}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ScanResultPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  async function handleDownloadReport() {
    if (!id) return;
    setDownloading(true);
    try {
      await downloadReport(id);
    } catch {
      // silently fail — browser will show nothing; could add a toast here
    } finally {
      setDownloading(false);
    }
  }

  useEffect(() => {
    if (!id) return;
    let timer: ReturnType<typeof setTimeout>;

    async function fetch() {
      try {
        const s = await getScan(id!);
        setScan(s);
        if (s.status === 'done' || s.status === 'error') {
          const f = await getFindings(id!);
          setFindings(f);
        } else {
          timer = setTimeout(fetch, POLL_INTERVAL);
        }
      } catch {
        setError('Failed to load scan. Please refresh.');
      }
    }

    void fetch();
    return () => clearTimeout(timer);
  }, [id]);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center text-red-400 gap-2">
        <XCircle className="w-5 h-5" /> {error}
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center gap-2 text-gray-400">
        <Loader2 className="w-5 h-5 animate-spin" /> Loading scan…
      </div>
    );
  }

  const isAnalyzing = scan.status === 'pending' || scan.status === 'analyzing';
  const grouped = SEVERITY_ORDER.reduce<Record<string, Finding[]>>((acc, sev) => {
    acc[sev] = findings.filter(f => f.severity === sev);
    return acc;
  }, {} as Record<string, Finding[]>);

  return (
    <div className="min-h-screen px-4 py-8 max-w-3xl mx-auto">
      {/* Back */}
      <Link to="/scans" className="inline-flex items-center gap-1 text-sm text-indigo-400 hover:text-indigo-300 mb-6">
        <ArrowLeft className="w-4 h-4" /> Scan history
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-8 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Shield className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl font-bold break-all">{scan.filename}</h1>
          </div>
          <p className="text-xs text-gray-500">
            Submitted {new Date(scan.createdAt).toLocaleString()}
            {scan.completedAt && ` · Completed ${new Date(scan.completedAt).toLocaleString()}`}
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <VerdictBadge verdict={scan.verdict} />
          {scan.status === 'done' && (
            <button
              onClick={handleDownloadReport}
              disabled={downloading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-indigo-700 hover:bg-indigo-600 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
            >
              {downloading
                ? <Loader2 className="w-4 h-4 animate-spin" />
                : <FileDown className="w-4 h-4" />}
              {downloading ? 'Generating…' : 'Download Report'}
            </button>
          )}
        </div>
      </div>

      {/* Analyzing state */}
      {isAnalyzing && (
        <div className="bg-gray-900 rounded-xl p-6 flex items-center gap-4 mb-6">
          <Loader2 className="w-6 h-6 text-indigo-400 animate-spin shrink-0" />
          <div>
            <p className="font-medium">Analyzing APK…</p>
            <p className="text-sm text-gray-400 mt-0.5">This usually takes 20–60 seconds. The page updates automatically.</p>
          </div>
        </div>
      )}

      {/* Error from scan */}
      {scan.status === 'error' && scan.errorMessage && (
        <div className="bg-red-950 border border-red-700 rounded-xl p-4 mb-6 text-red-300 text-sm">
          <span className="font-semibold">Analysis failed: </span>{scan.errorMessage}
        </div>
      )}

      {/* Risk score */}
      {scan.status === 'done' && scan.riskScore !== null && (
        <div className="bg-gray-900 rounded-xl p-5 mb-6">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Risk Score</p>
          <RiskMeter score={scan.riskScore} />
        </div>
      )}

      {/* PHA categories */}
      {scan.phaCategories.length > 0 && (
        <div className="bg-gray-900 rounded-xl p-5 mb-6">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">PHA Categories Detected</p>
          <div className="flex flex-wrap gap-2">
            {scan.phaCategories.map(cat => (
              <span key={cat} className="bg-red-900/50 border border-red-700 text-red-300 text-xs px-2.5 py-1 rounded-full">
                {cat}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* APK Metadata */}
      <div className="bg-gray-900 rounded-xl p-5 mb-6">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">APK Metadata</p>
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <div>
            <dt className="text-gray-500 text-xs mb-0.5">Filename</dt>
            <dd className="text-gray-200 break-all">{scan.filename}</dd>
          </div>
          <div>
            <dt className="text-gray-500 text-xs mb-0.5">SHA-256</dt>
            <dd className="text-gray-200 font-mono text-xs break-all">{scan.fileHashSha256}</dd>
          </div>
          <div>
            <dt className="text-gray-500 text-xs mb-0.5">Status</dt>
            <dd className="text-gray-200 capitalize">{scan.status}</dd>
          </div>
          {scan.completedAt && (
            <div>
              <dt className="text-gray-500 text-xs mb-0.5">Completed</dt>
              <dd className="text-gray-200">{new Date(scan.completedAt).toLocaleString()}</dd>
            </div>
          )}
        </dl>
      </div>

      {/* Findings */}
      {scan.status === 'done' && (
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">
            Findings ({findings.length})
          </p>
          {findings.length === 0 ? (
            <div className="bg-green-950 border border-green-800 rounded-xl p-5 flex items-center gap-3 text-green-300">
              <CheckCircle className="w-5 h-5 shrink-0" />
              <span>No findings detected. This APK appears clean.</span>
            </div>
          ) : (
            SEVERITY_ORDER.map(sev => (
              <FindingGroup key={sev} severity={sev} findings={grouped[sev]} />
            ))
          )}
        </div>
      )}
    </div>
  );
}
