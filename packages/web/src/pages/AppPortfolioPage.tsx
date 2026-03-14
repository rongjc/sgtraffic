import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Upload, BarChart2, Layers, Loader2, CheckCircle,
  XCircle, AlertTriangle, Clock, TrendingUp, TrendingDown, Minus,
  GitCompare,
} from 'lucide-react';
import { listScans, type Scan } from '../api';

// ── Types ─────────────────────────────────────────────────────────────────

interface AppEntry {
  appName: string;
  scans: Scan[];               // all scans, newest first
  latest: Scan;
  riskTrend: number[];         // last N risk scores (oldest→newest), nulls excluded
  totalScans: number;
  uniqueVersions: number;
  verdictCounts: Record<Scan['verdict'], number>;
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Normalize a filename to an "app name" by stripping extension and version suffixes. */
function toAppName(filename: string): string {
  // Remove extension
  let name = filename.replace(/\.(apk|ipa|zip|appx|msix)$/i, '');
  // Strip common version patterns: _v1.2.3, -1.2.3, _1.2.3, (1), [2], _debug, _release
  name = name.replace(/[-_]\d+(\.\d+){1,3}([-_]\w+)?$/, '');
  name = name.replace(/[_-](debug|release|unsigned|signed)$/i, '');
  name = name.replace(/\s*\(\d+\)$/, '');
  name = name.replace(/\s*\[\d+\]$/, '');
  return name.trim() || filename;
}

function groupByApp(scans: Scan[]): AppEntry[] {
  const map = new Map<string, Scan[]>();

  for (const scan of scans) {
    const key = toAppName(scan.filename);
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(scan);
  }

  const entries: AppEntry[] = [];

  for (const [appName, appScans] of map.entries()) {
    // newest first
    const sorted = [...appScans].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
    const riskTrend = sorted
      .slice()
      .reverse() // oldest first
      .map(s => s.riskScore)
      .filter((r): r is number => r !== null && r !== undefined);

    const verdictCounts: Record<Scan['verdict'], number> = {
      clean: 0, pha: 0, suspicious: 0, unknown: 0,
    };
    for (const s of sorted) verdictCounts[s.verdict]++;

    entries.push({
      appName,
      scans: sorted,
      latest: sorted[0],
      riskTrend,
      totalScans: sorted.length,
      uniqueVersions: new Set(sorted.map(s => s.filename)).size,
      verdictCounts,
    });
  }

  // Sort by most recent scan first
  return entries.sort(
    (a, b) => new Date(b.latest.createdAt).getTime() - new Date(a.latest.createdAt).getTime(),
  );
}

// ── Sub-components ────────────────────────────────────────────────────────

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

function riskColor(score: number | null) {
  if (score === null) return 'text-gray-500';
  if (score >= 75) return 'text-red-400';
  if (score >= 40) return 'text-yellow-400';
  return 'text-green-400';
}

/** Tiny inline sparkline for risk trend. */
function RiskSparkline({ scores }: { scores: number[] }) {
  if (scores.length < 2) {
    if (scores.length === 1) {
      return (
        <span className={`text-xs font-mono font-bold ${riskColor(scores[0])}`}>{scores[0]}</span>
      );
    }
    return <span className="text-xs text-gray-600">—</span>;
  }

  const w = 80;
  const h = 24;
  const maxVal = Math.max(...scores, 1);
  const minVal = Math.min(...scores);
  const range = maxVal - minVal || 1;
  const step = w / (scores.length - 1);

  const points = scores
    .map((v, i) => {
      const x = i * step;
      const y = h - ((v - minVal) / range) * (h - 4) - 2;
      return `${x},${y}`;
    })
    .join(' ');

  const latest = scores[scores.length - 1];
  const prev = scores[scores.length - 2];
  const delta = latest - prev;

  const lineColor = latest >= 75 ? '#f87171' : latest >= 40 ? '#facc15' : '#4ade80';

  return (
    <div className="flex items-center gap-2">
      <svg width={w} height={h} className="overflow-visible">
        <polyline
          points={points}
          fill="none"
          stroke={lineColor}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          opacity="0.7"
        />
        {/* Latest dot */}
        {scores.map((v, i) => {
          const x = i * step;
          const y = h - ((v - minVal) / range) * (h - 4) - 2;
          return i === scores.length - 1 ? (
            <circle key={i} cx={x} cy={y} r="3" fill={lineColor} />
          ) : null;
        })}
      </svg>
      <div className="flex flex-col items-end">
        <span className={`text-xs font-bold font-mono ${riskColor(latest)}`}>{latest}</span>
        {Math.abs(delta) > 0 && (
          <span className={`text-[10px] font-mono leading-none ${delta > 0 ? 'text-red-400' : 'text-green-400'}`}>
            {delta > 0 ? '+' : ''}{delta}
          </span>
        )}
      </div>
    </div>
  );
}

function TrendIcon({ scores }: { scores: number[] }) {
  if (scores.length < 2) return <Minus className="w-4 h-4 text-gray-600" />;
  const delta = scores[scores.length - 1] - scores[scores.length - 2];
  if (delta > 5) return <TrendingUp className="w-4 h-4 text-red-400" />;
  if (delta < -5) return <TrendingDown className="w-4 h-4 text-green-400" />;
  return <Minus className="w-4 h-4 text-gray-500" />;
}

function ScanHistoryMini({ scans }: { scans: Scan[] }) {
  const shown = scans.slice(0, 6);
  return (
    <div className="mt-3 space-y-1.5">
      {shown.map(scan => (
        <Link
          key={scan.id}
          to={`/scans/${scan.id}`}
          className="flex items-center gap-2 text-xs text-gray-400 hover:text-gray-200 transition-colors group"
        >
          <span className="text-gray-600 tabular-nums w-20 shrink-0">
            {new Date(scan.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: '2-digit' })}
          </span>
          <span className="truncate group-hover:text-indigo-300">{scan.filename}</span>
          {scan.riskScore !== null && (
            <span className={`shrink-0 font-mono font-bold ${riskColor(scan.riskScore)}`}>{scan.riskScore}</span>
          )}
        </Link>
      ))}
      {scans.length > 6 && (
        <p className="text-xs text-gray-600 pl-22">+{scans.length - 6} more</p>
      )}
    </div>
  );
}

// ── App Card ──────────────────────────────────────────────────────────────

function AppCard({ entry, expanded, onToggle }: {
  entry: AppEntry;
  expanded: boolean;
  onToggle: () => void;
}) {
  const hasMalware = entry.verdictCounts.pha > 0;
  const hasSuspicious = entry.verdictCounts.suspicious > 0;
  const borderColor = hasMalware
    ? 'border-red-800/50'
    : hasSuspicious
    ? 'border-yellow-800/50'
    : 'border-gray-800';

  return (
    <div className={`bg-gray-900 rounded-xl border ${borderColor} overflow-hidden`}>
      <button
        onClick={onToggle}
        className="w-full text-left px-5 py-4 flex items-center gap-4 hover:bg-gray-800/40 transition-colors"
      >
        {/* App name + verdict */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold text-sm text-gray-100 truncate">{entry.appName}</span>
            <TrendIcon scores={entry.riskTrend} />
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <VerdictChip verdict={entry.latest.verdict} />
            <span className="text-xs text-gray-600">
              {entry.totalScans} scan{entry.totalScans !== 1 ? 's' : ''}
              {entry.uniqueVersions > 1 && ` · ${entry.uniqueVersions} versions`}
            </span>
            <span className="text-xs text-gray-600">
              Last: {new Date(entry.latest.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
            </span>
          </div>
        </div>

        {/* Risk trend sparkline */}
        <div className="shrink-0">
          <RiskSparkline scores={entry.riskTrend} />
        </div>

        {/* Verdict distribution pills */}
        <div className="hidden sm:flex gap-1.5 shrink-0">
          {entry.verdictCounts.pha > 0 && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-red-900/40 text-red-300 font-medium">
              {entry.verdictCounts.pha}✗
            </span>
          )}
          {entry.verdictCounts.suspicious > 0 && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-900/40 text-yellow-300 font-medium">
              {entry.verdictCounts.suspicious}⚠
            </span>
          )}
          {entry.verdictCounts.clean > 0 && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-green-900/40 text-green-300 font-medium">
              {entry.verdictCounts.clean}✓
            </span>
          )}
        </div>

        {/* Action links */}
        <div className="flex gap-2 shrink-0">
          <Link
            to={`/scans/${entry.latest.id}`}
            onClick={e => e.stopPropagation()}
            className="text-xs text-indigo-400 hover:text-indigo-300 px-2 py-1 rounded bg-indigo-900/20 hover:bg-indigo-900/40 transition-colors"
          >
            Latest
          </Link>
          {entry.scans.length >= 2 && (
            <Link
              to={`/compare?a=${entry.scans[1].id}&b=${entry.scans[0].id}`}
              onClick={e => e.stopPropagation()}
              className="text-xs text-gray-400 hover:text-gray-300 px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 transition-colors"
            >
              Compare
            </Link>
          )}
        </div>
      </button>

      {expanded && (
        <div className="px-5 pb-4 border-t border-gray-800/60 pt-3">
          <ScanHistoryMini scans={entry.scans} />
        </div>
      )}
    </div>
  );
}

// ── Summary bar ───────────────────────────────────────────────────────────

function PortfolioSummary({ entries }: { entries: AppEntry[] }) {
  const totalApps = entries.length;
  const atRisk = entries.filter(e => e.latest.verdict === 'pha' || e.latest.verdict === 'suspicious').length;
  const clean = entries.filter(e => e.latest.verdict === 'clean').length;
  const avgRisk = (() => {
    const scores = entries
      .map(e => e.riskTrend[e.riskTrend.length - 1])
      .filter((s): s is number => s !== undefined);
    if (scores.length === 0) return null;
    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  })();

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
      {[
        { label: 'Total Apps', value: totalApps, color: 'text-white' },
        { label: 'At Risk', value: atRisk, color: atRisk > 0 ? 'text-red-400' : 'text-green-400' },
        { label: 'Clean', value: clean, color: 'text-green-400' },
        { label: 'Avg Risk Score', value: avgRisk !== null ? avgRisk : '—', color: riskColor(avgRisk) },
      ].map(({ label, value, color }) => (
        <div key={label} className="bg-gray-900 rounded-xl p-4">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{label}</p>
          <p className={`text-2xl font-bold ${color}`}>{value}</p>
        </div>
      ))}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function AppPortfolioPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedApp, setExpandedApp] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'at_risk' | 'clean'>('all');

  useEffect(() => {
    listScans()
      .then(data => setScans(data))
      .catch(() => setError('Failed to load scan history.'))
      .finally(() => setLoading(false));
  }, []);

  const entries = groupByApp(scans);

  const filtered = entries.filter(e => {
    if (filter === 'at_risk') return e.latest.verdict === 'pha' || e.latest.verdict === 'suspicious';
    if (filter === 'clean') return e.latest.verdict === 'clean';
    return true;
  });

  return (
    <div className="min-h-screen px-4 py-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Layers className="w-6 h-6 text-indigo-400" />
            <h1 className="text-2xl font-bold">App Portfolio</h1>
          </div>
          <p className="text-sm text-gray-500 ml-9">Track all scanned apps, their risk trends, and scan history.</p>
        </div>
        <div className="flex gap-3">
          <Link to="/compare" className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <GitCompare className="w-4 h-4" /> Compare
          </Link>
          <Link to="/metrics" className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <BarChart2 className="w-4 h-4" /> Analytics
          </Link>
          <Link to="/" className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Upload className="w-4 h-4" /> New Scan
          </Link>
        </div>
      </div>

      {error && (
        <div className="bg-red-950 border border-red-700 rounded-xl p-4 text-red-300 text-sm mb-6">{error}</div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-20 gap-2 text-gray-400">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading portfolio…
        </div>
      ) : entries.length === 0 ? (
        <div className="text-center py-20 text-gray-500">
          <Shield className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium mb-2">No apps yet</p>
          <p className="text-sm">Upload an APK or IPA to start building your portfolio.</p>
        </div>
      ) : (
        <>
          <PortfolioSummary entries={entries} />

          {/* Filter tabs */}
          <div className="flex gap-2 mb-4">
            {([
              { key: 'all', label: `All (${entries.length})` },
              { key: 'at_risk', label: `At Risk (${entries.filter(e => e.latest.verdict === 'pha' || e.latest.verdict === 'suspicious').length})` },
              { key: 'clean', label: `Clean (${entries.filter(e => e.latest.verdict === 'clean').length})` },
            ] as const).map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setFilter(key)}
                className={`text-xs px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  filter === key
                    ? 'bg-indigo-600 text-white'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* App cards */}
          <div className="space-y-3">
            {filtered.map(entry => (
              <AppCard
                key={entry.appName}
                entry={entry}
                expanded={expandedApp === entry.appName}
                onToggle={() => setExpandedApp(p => p === entry.appName ? null : entry.appName)}
              />
            ))}
            {filtered.length === 0 && (
              <p className="text-center text-gray-600 py-8 text-sm">No apps match this filter.</p>
            )}
          </div>
        </>
      )}
    </div>
  );
}
