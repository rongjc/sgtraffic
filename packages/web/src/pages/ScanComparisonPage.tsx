import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Shield, Upload, BarChart2, ArrowLeft, Loader2, CheckCircle,
  XCircle, AlertTriangle, Clock, GitCompare, ArrowRight, Layers, LogIn,
} from 'lucide-react';
import { listScans, getScan, getFindings, type Scan, type Finding } from '../api';

// ── Helpers ────────────────────────────────────────────────────────────────

function verdictConfig(verdict: Scan['verdict']) {
  const map = {
    clean:      { label: 'Clean',      cls: 'bg-green-900/50 text-green-300 border-green-700',   Icon: CheckCircle },
    pha:        { label: 'Malware',    cls: 'bg-red-900/50 text-red-300 border-red-700',         Icon: XCircle },
    suspicious: { label: 'Suspicious', cls: 'bg-yellow-900/50 text-yellow-300 border-yellow-700', Icon: AlertTriangle },
    unknown:    { label: 'Pending',    cls: 'bg-gray-800 text-gray-400 border-gray-700',          Icon: Clock },
  };
  return map[verdict];
}

function riskColor(score: number | null) {
  if (score === null) return 'text-gray-500';
  if (score >= 75) return 'text-red-400';
  if (score >= 40) return 'text-yellow-400';
  return 'text-green-400';
}

function RiskBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-gray-500 text-sm">—</span>;
  const color = score >= 75 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500';
  return (
    <div className="flex items-center gap-2 flex-1">
      <div className="flex-1 bg-gray-800 rounded-full h-2.5 overflow-hidden">
        <div className={`h-2.5 rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-sm font-bold w-8 text-right font-mono ${riskColor(score)}`}>{score}</span>
    </div>
  );
}

// ── Skeleton loader ─────────────────────────────────────────────────────────

function SkeletonBlock({ className = '' }: { className?: string }) {
  return <div className={`bg-gray-800 animate-pulse rounded ${className}`} />;
}

function ComparisonSkeleton() {
  return (
    <div className="space-y-4 mt-6" aria-label="Loading comparison…" aria-busy="true">
      {/* Column headers */}
      <div className="grid grid-cols-2 gap-4 px-1">
        <SkeletonBlock className="h-20" />
        <SkeletonBlock className="h-20" />
      </div>
      {/* Sections */}
      {[1, 2, 3].map(i => (
        <div key={i} className="bg-gray-900 rounded-xl overflow-hidden">
          <SkeletonBlock className="h-10 rounded-none" />
          <div className="p-5 space-y-3">
            <SkeletonBlock className="h-4 w-3/4" />
            <SkeletonBlock className="h-4 w-1/2" />
            <SkeletonBlock className="h-4 w-2/3" />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Scan picker ────────────────────────────────────────────────────────────

interface PickerProps {
  label: string;
  scans: Scan[];
  selectedId: string | null;
  disabledId: string | null;
  onSelect: (id: string) => void;
}

function ScanPicker({ label, scans, selectedId, disabledId, onSelect }: PickerProps) {
  return (
    <div className="bg-gray-900 rounded-xl overflow-hidden flex-1 min-w-0" role="listbox" aria-label={label}>
      <div className="px-4 py-3 border-b border-gray-800">
        <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
        {selectedId && (
          <p className="text-sm font-medium text-indigo-300 mt-0.5 truncate">
            {scans.find(s => s.id === selectedId)?.filename ?? selectedId}
          </p>
        )}
      </div>
      <div className="divide-y divide-gray-800 max-h-72 overflow-y-auto">
        {scans.map(scan => {
          const isSelected = scan.id === selectedId;
          const isDisabled = scan.id === disabledId;
          const vc = verdictConfig(scan.verdict);
          return (
            <button
              key={scan.id}
              role="option"
              aria-selected={isSelected}
              disabled={isDisabled}
              onClick={() => onSelect(scan.id)}
              className={`w-full text-left px-4 py-3 flex items-center gap-3 transition-colors
                ${isSelected ? 'bg-indigo-900/40 border-l-2 border-indigo-500' : ''}
                ${isDisabled ? 'opacity-30 cursor-not-allowed' : 'hover:bg-gray-800/60 cursor-pointer'}
              `}
            >
              <vc.Icon className={`w-4 h-4 shrink-0 ${vc.cls.split(' ')[1]}`} aria-hidden="true" />
              <span className="flex-1 text-sm text-gray-200 truncate">{scan.filename}</span>
              <span className="text-xs text-gray-500 whitespace-nowrap">
                {new Date(scan.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
              </span>
              {scan.riskScore !== null && (
                <span className={`text-xs font-mono font-bold ${riskColor(scan.riskScore)}`} aria-label={`Risk score ${scan.riskScore}`}>
                  {scan.riskScore}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Comparison panel ───────────────────────────────────────────────────────

type ScanWithFindings = { scan: Scan; findings: Finding[] };

function ComparisonSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-gray-900 rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-gray-800">
        <h3 className="text-xs text-gray-500 uppercase tracking-wider font-semibold">{title}</h3>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function TagList({ items, colorClass }: { items: string[]; colorClass: string }) {
  if (items.length === 0) return <span className="text-gray-600 text-xs">None</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map(item => (
        <span key={item} className={`text-xs px-2 py-0.5 rounded-full border ${colorClass}`}>{item}</span>
      ))}
    </div>
  );
}

// Issue 2: DiffTagList uses both visual (color/strikethrough) and textual cues (WCAG 1.4.1)
function DiffTagList({ a, b, colorClass }: { a: string[]; b: string[]; colorClass: string }) {
  const setA = new Set(a);
  const setB = new Set(b);
  const allItems = [...new Set([...a, ...b])];
  if (allItems.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1.5" role="list">
      {allItems.map(item => {
        const inA = setA.has(item);
        const inB = setB.has(item);
        if (inA && inB) {
          return (
            <span key={item} className={`text-xs px-2 py-0.5 rounded-full border ${colorClass}`} role="listitem" aria-label={`${item} – unchanged`}>
              {item}
            </span>
          );
        }
        if (inA && !inB) {
          return (
            <span key={item} className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border border-red-700 bg-red-900/30 text-red-300" role="listitem" aria-label={`${item} – resolved (removed)`}>
              <span className="font-semibold uppercase tracking-wide text-[10px]">RESOLVED</span>
              <span className="line-through opacity-60">{item}</span>
            </span>
          );
        }
        return (
          <span key={item} className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border border-green-700 bg-green-900/30 text-green-300" role="listitem" aria-label={`${item} – new (added)`}>
            <span className="font-semibold uppercase tracking-wide text-[10px]">NEW</span>
            {item}
          </span>
        );
      })}
    </div>
  );
}

function ComparisonPanel({ left, right }: { left: ScanWithFindings; right: ScanWithFindings }) {
  const severities: Finding['severity'][] = ['critical', 'high', 'medium', 'low'];

  const countBySev = (findings: Finding[], sev: Finding['severity']) =>
    findings.filter(f => f.severity === sev).length;

  const sevColor: Record<Finding['severity'], string> = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
  };

  const riskDiff =
    left.scan.riskScore !== null && right.scan.riskScore !== null
      ? right.scan.riskScore - left.scan.riskScore
      : null;

  // Issue 4: detect identical scans
  const isIdentical =
    left.scan.riskScore === right.scan.riskScore &&
    left.findings.length === right.findings.length &&
    severities.every(sev => countBySev(left.findings, sev) === countBySev(right.findings, sev)) &&
    JSON.stringify([...left.scan.phaCategories].sort()) === JSON.stringify([...right.scan.phaCategories].sort()) &&
    JSON.stringify([...(left.scan.trackersDetected ?? [])].sort()) ===
      JSON.stringify([...(right.scan.trackersDetected ?? [])].sort());

  if (isIdentical) {
    return (
      <div className="mt-6 bg-green-950 border border-green-800 rounded-xl p-8 text-center" role="status">
        <CheckCircle className="w-10 h-10 text-green-400 mx-auto mb-3" aria-hidden="true" />
        <p className="text-green-300 font-semibold text-lg">No differences found — these two scans are identical</p>
        <div className="mt-4 flex flex-col sm:flex-row justify-center gap-4 text-sm text-gray-400">
          <span>
            <span className="text-gray-300 font-medium">Scan A:</span>{' '}
            {left.scan.filename}{' '}
            <span className="text-gray-600">({new Date(left.scan.createdAt).toLocaleDateString()})</span>
          </span>
          <span className="hidden sm:inline text-gray-700">vs</span>
          <span>
            <span className="text-gray-300 font-medium">Scan B:</span>{' '}
            {right.scan.filename}{' '}
            <span className="text-gray-600">({new Date(right.scan.createdAt).toLocaleDateString()})</span>
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 mt-6">

      {/* Column headers */}
      <div className="grid grid-cols-2 gap-4 px-1">
        {[left, right].map((sw, i) => {
          const vc = verdictConfig(sw.scan.verdict);
          return (
            <div key={i} className="bg-gray-900 rounded-xl p-4">
              <Link
                to={`/scans/${sw.scan.id}`}
                className="text-sm font-semibold text-indigo-300 hover:text-indigo-200 flex items-center gap-1.5 truncate mb-2"
              >
                {sw.scan.filename}
                <ArrowRight className="w-3 h-3 shrink-0" aria-hidden="true" />
              </Link>
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border font-medium ${vc.cls}`}>
                  <vc.Icon className="w-3 h-3" aria-hidden="true" /> {vc.label}
                </span>
                <span className="text-xs text-gray-500">
                  {new Date(sw.scan.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Risk score */}
      <ComparisonSection title="Risk Score">
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-6">
            <div className="flex items-center gap-3">
              <span className="text-xs text-gray-500 w-5 shrink-0" aria-label="Scan A">A</span>
              <RiskBar score={left.scan.riskScore} />
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-gray-500 w-5 shrink-0" aria-label="Scan B">B</span>
              <RiskBar score={right.scan.riskScore} />
            </div>
          </div>
          {riskDiff !== null && (
            <div className="flex items-center gap-2 pt-1">
              <span className="text-xs text-gray-500">Change:</span>
              <span
                className={`text-sm font-bold font-mono ${riskDiff > 0 ? 'text-red-400' : riskDiff < 0 ? 'text-green-400' : 'text-gray-400'}`}
                aria-label={`Risk score change: ${riskDiff > 0 ? '+' : ''}${riskDiff} (B minus A)`}
              >
                {riskDiff > 0 ? '+' : ''}{riskDiff}
              </span>
              <span className="text-xs text-gray-600" aria-hidden="true">(B − A)</span>
            </div>
          )}
        </div>
      </ComparisonSection>

      {/* Findings breakdown — Issue 2: accessible diff badges */}
      <ComparisonSection title="Findings by Severity">
        <div className="space-y-2" role="table" aria-label="Findings by severity comparison">
          {severities.map(sev => {
            const lc = countBySev(left.findings, sev);
            const rc = countBySev(right.findings, sev);
            const delta = rc - lc;
            const changed = lc !== rc;
            // WCAG 1.4.1: use text badge alongside color arrow
            let diffLabel = 'UNCHANGED';
            let diffCls = 'text-gray-600 bg-gray-800';
            if (changed) {
              diffLabel = delta > 0 ? 'NEW ↑' : 'RESOLVED ↓';
              diffCls = delta > 0 ? 'text-red-300 bg-red-900/40 border border-red-800' : 'text-green-300 bg-green-900/40 border border-green-800';
            }
            return (
              <div
                key={sev}
                className="grid grid-cols-[80px_1fr_auto_1fr] gap-3 items-center"
                role="row"
                aria-label={`${sev}: Scan A has ${lc}, Scan B has ${rc}${changed ? `, ${diffLabel}` : ', unchanged'}`}
              >
                <span className={`text-xs capitalize font-semibold ${sevColor[sev]}`} role="cell">{sev}</span>
                <div className="flex justify-end" role="cell">
                  <span className={`text-sm font-mono font-bold ${sevColor[sev]}`}>{lc}</span>
                </div>
                <span
                  className={`text-center text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded ${diffCls}`}
                  role="cell"
                  aria-hidden="true"
                >
                  {changed ? diffLabel : '='}
                </span>
                <div className="flex items-center gap-1.5" role="cell">
                  <span className={`text-sm font-mono font-bold ${sevColor[sev]}`}>{rc}</span>
                  {changed && (
                    <span className={`text-xs font-mono ${delta > 0 ? 'text-red-400' : 'text-green-400'}`} aria-hidden="true">
                      ({delta > 0 ? '+' : ''}{delta})
                    </span>
                  )}
                </div>
              </div>
            );
          })}
          {/* Total row */}
          {(() => {
            const lt = left.findings.length;
            const rt = right.findings.length;
            const dt = rt - lt;
            const changed = lt !== rt;
            return (
              <div
                className="grid grid-cols-[80px_1fr_auto_1fr] gap-3 items-center pt-1 border-t border-gray-800 mt-2"
                role="row"
                aria-label={`Total: Scan A has ${lt}, Scan B has ${rt}${changed ? `, ${dt > 0 ? 'increased' : 'decreased'} by ${Math.abs(dt)}` : ', unchanged'}`}
              >
                <span className="text-xs text-gray-500" role="cell">Total</span>
                <div className="flex justify-end" role="cell">
                  <span className="text-sm font-mono font-bold text-gray-300">{lt}</span>
                </div>
                <span
                  className={`text-center text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded ${changed ? (dt > 0 ? 'text-red-300 bg-red-900/40 border border-red-800' : 'text-green-300 bg-green-900/40 border border-green-800') : 'text-gray-600 bg-gray-800'}`}
                  role="cell"
                  aria-hidden="true"
                >
                  {changed ? (dt > 0 ? '↑' : '↓') : '='}
                </span>
                <div className="flex items-center gap-1.5" role="cell">
                  <span className="text-sm font-mono font-bold text-gray-300">{rt}</span>
                  {changed && (
                    <span className={`text-xs font-mono ${dt > 0 ? 'text-red-400' : 'text-green-400'}`} aria-hidden="true">
                      ({dt > 0 ? '+' : ''}{dt})
                    </span>
                  )}
                </div>
              </div>
            );
          })()}
        </div>
      </ComparisonSection>

      {/* PHA categories diff */}
      <ComparisonSection title="PHA Categories">
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-gray-600 mb-2">Scan A</p>
              <TagList items={left.scan.phaCategories} colorClass="border-red-700 bg-red-900/30 text-red-300" />
            </div>
            <div>
              <p className="text-xs text-gray-600 mb-2">Scan B</p>
              <TagList items={right.scan.phaCategories} colorClass="border-red-700 bg-red-900/30 text-red-300" />
            </div>
          </div>
          {(left.scan.phaCategories.length > 0 || right.scan.phaCategories.length > 0) && (
            <div className="pt-3 border-t border-gray-800">
              <p className="text-xs text-gray-500 mb-2">Changes (NEW = added in B, RESOLVED = removed from B)</p>
              <DiffTagList
                a={left.scan.phaCategories}
                b={right.scan.phaCategories}
                colorClass="border-red-700 bg-red-900/30 text-red-300"
              />
            </div>
          )}
        </div>
      </ComparisonSection>

      {/* Tracker diff */}
      {(left.scan.trackersDetected?.length || right.scan.trackersDetected?.length) ? (
        <ComparisonSection title="Tracker SDKs">
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-gray-600 mb-2">Scan A</p>
                <TagList
                  items={left.scan.trackersDetected ?? []}
                  colorClass="border-purple-700 bg-purple-900/30 text-purple-300"
                />
              </div>
              <div>
                <p className="text-xs text-gray-600 mb-2">Scan B</p>
                <TagList
                  items={right.scan.trackersDetected ?? []}
                  colorClass="border-purple-700 bg-purple-900/30 text-purple-300"
                />
              </div>
            </div>
            <div className="pt-3 border-t border-gray-800">
              <p className="text-xs text-gray-500 mb-2">Changes (NEW = added in B, RESOLVED = removed from B)</p>
              <DiffTagList
                a={left.scan.trackersDetected ?? []}
                b={right.scan.trackersDetected ?? []}
                colorClass="border-purple-700 bg-purple-900/30 text-purple-300"
              />
            </div>
          </div>
        </ComparisonSection>
      ) : null}

      {/* Rule diff */}
      <ComparisonSection title="Unique Rules Triggered">
        {(() => {
          const leftRules = new Set(left.findings.map(f => f.rule));
          const rightRules = new Set(right.findings.map(f => f.rule));
          const onlyLeft = [...leftRules].filter(r => !rightRules.has(r));
          const onlyRight = [...rightRules].filter(r => !leftRules.has(r));
          const shared = [...leftRules].filter(r => rightRules.has(r));
          return (
            <div className="space-y-3 text-xs">
              {shared.length > 0 && (
                <div>
                  <p className="text-gray-500 mb-1.5">Shared ({shared.length}) — <span className="text-gray-600">unchanged in both scans</span></p>
                  <div className="flex flex-wrap gap-1.5" role="list" aria-label="Unchanged rules">
                    {shared.map(r => (
                      <span key={r} className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 font-mono" role="listitem">{r}</span>
                    ))}
                  </div>
                </div>
              )}
              {onlyLeft.length > 0 && (
                <div>
                  <p className="text-gray-500 mb-1.5">
                    <span className="inline-block text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded text-green-300 bg-green-900/40 border border-green-800 mr-1.5">RESOLVED</span>
                    Only in A ({onlyLeft.length}) — removed in Scan B
                  </p>
                  <div className="flex flex-wrap gap-1.5" role="list" aria-label="Resolved rules">
                    {onlyLeft.map(r => (
                      <span key={r} className="px-2 py-0.5 rounded bg-red-900/30 text-red-300 border border-red-800 font-mono" role="listitem">{r}</span>
                    ))}
                  </div>
                </div>
              )}
              {onlyRight.length > 0 && (
                <div>
                  <p className="text-gray-500 mb-1.5">
                    <span className="inline-block text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded text-red-300 bg-red-900/40 border border-red-800 mr-1.5">NEW</span>
                    Only in B ({onlyRight.length}) — new in Scan B
                  </p>
                  <div className="flex flex-wrap gap-1.5" role="list" aria-label="New rules">
                    {onlyRight.map(r => (
                      <span key={r} className="px-2 py-0.5 rounded bg-green-900/30 text-green-300 border border-green-800 font-mono" role="listitem">{r}</span>
                    ))}
                  </div>
                </div>
              )}
              {shared.length === 0 && onlyLeft.length === 0 && onlyRight.length === 0 && (
                <p className="text-gray-600">No findings in either scan.</p>
              )}
            </div>
          );
        })()}
      </ComparisonSection>

    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function ScanComparisonPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  // Issue 3: track unauthenticated state
  const [isUnauthenticated, setIsUnauthenticated] = useState(false);

  const [leftData, setLeftData] = useState<ScanWithFindings | null>(null);
  const [rightData, setRightData] = useState<ScanWithFindings | null>(null);
  const [loadingComparison, setLoadingComparison] = useState(false);
  const [compError, setCompError] = useState<string | null>(null);

  const selectedA = searchParams.get('a');
  const selectedB = searchParams.get('b');

  useEffect(() => {
    listScans()
      .then(data => setScans([...data].reverse()))
      .catch((err: { response?: { status: number } }) => {
        // Issue 3: detect auth errors explicitly — never silently fall back
        const status = err?.response?.status;
        if (status === 401 || status === 403) {
          setIsUnauthenticated(true);
        } else {
          setListError('Failed to load scan history.');
        }
      })
      .finally(() => setLoadingList(false));
  }, []);

  const loadComparison = useCallback(async (idA: string, idB: string) => {
    setLoadingComparison(true);
    setCompError(null);
    setLeftData(null);
    setRightData(null);
    try {
      const [scanA, scanB, findingsA, findingsB] = await Promise.all([
        getScan(idA),
        getScan(idB),
        getFindings(idA),
        getFindings(idB),
      ]);
      setLeftData({ scan: scanA, findings: findingsA });
      setRightData({ scan: scanB, findings: findingsB });
    } catch {
      setCompError('Failed to load one or both scans. Please try again.');
    } finally {
      setLoadingComparison(false);
    }
  }, []);

  useEffect(() => {
    if (selectedA && selectedB) {
      loadComparison(selectedA, selectedB);
    }
  }, [selectedA, selectedB, loadComparison]);

  function selectA(id: string) {
    setSearchParams(p => { p.set('a', id); return p; });
  }
  function selectB(id: string) {
    setSearchParams(p => { p.set('b', id); return p; });
  }
  // Issue 1 (mobile): swap button
  function swapScans() {
    setSearchParams(p => {
      const a = p.get('a');
      const b = p.get('b');
      if (b) p.set('a', b); else p.delete('a');
      if (a) p.set('b', a); else p.delete('b');
      return p;
    });
  }

  // Issue 3: unauthenticated state — show auth prompt, never a blank/silent fallback
  if (!loadingList && isUnauthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="bg-gray-900 rounded-2xl p-10 max-w-sm w-full text-center shadow-xl border border-gray-800">
          <LogIn className="w-10 h-10 text-indigo-400 mx-auto mb-4" aria-hidden="true" />
          <h2 className="text-xl font-bold mb-2">Sign in to compare scans</h2>
          <p className="text-sm text-gray-400 mb-6">
            Scan history is only available to signed-in users. Please log in to access the comparison tool.
          </p>
          <a
            href="/login"
            className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-6 py-3 rounded-xl transition-colors"
          >
            <LogIn className="w-4 h-4" aria-hidden="true" />
            Sign in
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen px-4 py-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <GitCompare className="w-6 h-6 text-indigo-400" aria-hidden="true" />
            <h1 className="text-2xl font-bold">Scan Comparison</h1>
          </div>
          <p className="text-sm text-gray-500 ml-9">Select two scans to diff their results side-by-side.</p>
        </div>
        <div className="flex gap-3">
          <Link to="/apps" className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Layers className="w-4 h-4" aria-hidden="true" /> Portfolio
          </Link>
          <Link to="/metrics" className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <BarChart2 className="w-4 h-4" aria-hidden="true" /> Analytics
          </Link>
          <Link to="/" className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Upload className="w-4 h-4" aria-hidden="true" /> New Scan
          </Link>
        </div>
      </div>

      {/* Back link */}
      <Link to="/scans" className="inline-flex items-center gap-1 text-sm text-indigo-400 hover:text-indigo-300 mb-6">
        <ArrowLeft className="w-4 h-4" aria-hidden="true" /> Scan history
      </Link>

      {listError && (
        <div className="bg-red-950 border border-red-700 rounded-xl p-4 text-red-300 text-sm mb-6" role="alert">{listError}</div>
      )}

      {loadingList ? (
        <div className="flex items-center justify-center py-16 gap-2 text-gray-400" aria-label="Loading scan list" aria-busy="true">
          <Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" /> Loading scans…
        </div>
      ) : scans.length < 2 ? (
        <div className="text-center py-16 text-gray-500" role="status">
          <Shield className="w-12 h-12 mx-auto mb-4 opacity-30" aria-hidden="true" />
          <p className="font-medium">Not enough scans</p>
          <p className="text-sm mt-1">You need at least 2 completed scans to compare.</p>
        </div>
      ) : (
        <>
          {/* Issue 1: Scan pickers — responsive, with mobile swap button */}
          <div className="flex flex-col sm:flex-row gap-4 items-stretch sm:items-start">
            <ScanPicker
              label="Scan A (baseline)"
              scans={scans}
              selectedId={selectedA}
              disabledId={selectedB}
              onSelect={selectA}
            />
            {/* Swap button — visible on all sizes, stacks naturally */}
            <div className="flex sm:flex-col items-center justify-center gap-2 flex-shrink-0 py-2 sm:pt-16">
              <button
                type="button"
                onClick={swapScans}
                disabled={!selectedA && !selectedB}
                className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                aria-label="Swap Scan A and Scan B"
                title="Swap A ↔ B"
              >
                <GitCompare className="w-4 h-4 text-gray-400" aria-hidden="true" />
              </button>
              <span className="text-[10px] text-gray-600 uppercase tracking-wider hidden sm:block">Swap</span>
            </div>
            <ScanPicker
              label="Scan B (compare)"
              scans={scans}
              selectedId={selectedB}
              disabledId={selectedA}
              onSelect={selectB}
            />
          </div>

          {!selectedA && !selectedB && (
            <p className="text-center text-gray-600 text-sm mt-8">
              ← Select a baseline scan (A) and a comparison scan (B) above.
            </p>
          )}
          {selectedA && !selectedB && (
            <p className="text-center text-gray-600 text-sm mt-8">Now select Scan B on the right →</p>
          )}

          {/* Issue 5: skeleton loader while comparison is loading */}
          {loadingComparison && <ComparisonSkeleton />}

          {/* Issue 5: error with retry button */}
          {compError && !loadingComparison && (
            <div className="bg-red-950 border border-red-700 rounded-xl p-4 mt-6 flex items-start justify-between gap-4" role="alert">
              <p className="text-red-300 text-sm">{compError}</p>
              {selectedA && selectedB && (
                <button
                  type="button"
                  onClick={() => loadComparison(selectedA, selectedB)}
                  className="shrink-0 text-sm text-red-300 underline hover:text-red-200"
                >
                  Retry
                </button>
              )}
            </div>
          )}

          {/* Issue 4: empty state handled inside ComparisonPanel */}
          {leftData && rightData && !loadingComparison && (
            <ComparisonPanel left={leftData} right={rightData} />
          )}
        </>
      )}
    </div>
  );
}
