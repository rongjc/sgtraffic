import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Upload, BarChart2, CheckCircle, XCircle,
  AlertTriangle, Clock, Loader2, TrendingUp, Zap, Eye,
  GitCompare, Layers,
} from 'lucide-react';
import { getMetrics, listScans, type Metrics, type Scan } from '../api';

// ── Mini bar chart (pure CSS/SVG, no extra deps) ──────────────────────────
function SparkBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
        <div className={`h-2 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-gray-400 w-8 text-right">{value}</span>
    </div>
  );
}

// ── Volume sparkline ───────────────────────────────────────────────────────
function VolumeSpark({ data }: { data: { date: string; count: number }[] }) {
  if (data.length === 0) {
    return <p className="text-gray-600 text-sm">No data yet.</p>;
  }
  const max = Math.max(...data.map(d => d.count), 1);
  const w = 400;
  const h = 60;
  const barW = Math.max(2, Math.floor((w - data.length) / data.length));
  const bars = data.map((d, i) => {
    const barH = Math.max(2, Math.round((d.count / max) * h));
    const x = i * (barW + 1);
    const y = h - barH;
    return (
      <rect key={d.date} x={x} y={y} width={barW} height={barH}
        className="fill-indigo-500" rx="1" />
    );
  });
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full" preserveAspectRatio="none" style={{ height: 60 }}>
        {bars}
      </svg>
      <div className="flex justify-between text-xs text-gray-600 mt-1">
        <span>{data[0]?.date}</span>
        <span>{data[data.length - 1]?.date}</span>
      </div>
    </div>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────
function StatCard({
  label, value, sub, color = 'text-white',
}: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-gray-900 rounded-xl p-5">
      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  );
}

// ── Verdict badge ─────────────────────────────────────────────────────────
const VERDICT_CFG = {
  clean:      { label: 'Clean',      cls: 'text-green-400',  Icon: CheckCircle },
  pha:        { label: 'Malware',    cls: 'text-red-400',    Icon: XCircle },
  suspicious: { label: 'Suspicious', cls: 'text-yellow-400', Icon: AlertTriangle },
  unknown:    { label: 'Unknown',    cls: 'text-gray-500',   Icon: Clock },
} as const;

// ── Threat Trend Chart ────────────────────────────────────────────────────

interface DayThreat {
  date: string;
  total: number;
  pha: number;
  suspicious: number;
  clean: number;
}

function buildThreatTrend(scans: Scan[], days = 30): DayThreat[] {
  const now = new Date();
  const result: DayThreat[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    result.push({ date: key, total: 0, pha: 0, suspicious: 0, clean: 0 });
  }
  const byDate = new Map(result.map(r => [r.date, r]));
  for (const s of scans) {
    const key = s.createdAt.slice(0, 10);
    const entry = byDate.get(key);
    if (!entry) continue;
    entry.total++;
    if (s.verdict === 'pha') entry.pha++;
    else if (s.verdict === 'suspicious') entry.suspicious++;
    else if (s.verdict === 'clean') entry.clean++;
  }
  return result;
}

function ThreatTrendChart({ scans }: { scans: Scan[] }) {
  const data = buildThreatTrend(scans, 30);
  const maxTotal = Math.max(...data.map(d => d.total), 1);
  const w = 560;
  const h = 80;
  const barW = Math.max(2, Math.floor((w - data.length) / data.length));

  return (
    <div>
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full" preserveAspectRatio="none" style={{ height: 80 }}>
        {data.map((d, i) => {
          const x = i * (barW + 1);
          const totalH = Math.max(d.total > 0 ? 2 : 0, Math.round((d.total / maxTotal) * h));
          const phaH = d.total > 0 ? Math.round((d.pha / d.total) * totalH) : 0;
          const suspH = d.total > 0 ? Math.round((d.suspicious / d.total) * totalH) : 0;
          const cleanH = totalH - phaH - suspH;
          let y = h - totalH;
          return (
            <g key={d.date}>
              {phaH > 0 && <rect x={x} y={y} width={barW} height={phaH} fill="#ef4444" rx="1" />}
              {(() => { const top = y; y += phaH; return suspH > 0 ? <rect x={x} y={top + phaH} width={barW} height={suspH} fill="#eab308" rx="1" /> : null; })()}
              {cleanH > 0 && <rect x={x} y={h - cleanH} width={barW} height={cleanH} fill="#22c55e" rx="1" opacity="0.5" />}
            </g>
          );
        })}
      </svg>
      <div className="flex justify-between text-xs text-gray-600 mt-1">
        <span>{data[0]?.date}</span>
        <span>{data[data.length - 1]?.date}</span>
      </div>
      <div className="flex gap-4 mt-2">
        {[
          { color: 'bg-red-500', label: 'Malware' },
          { color: 'bg-yellow-500', label: 'Suspicious' },
          { color: 'bg-green-500 opacity-50', label: 'Clean' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className={`w-2.5 h-2.5 rounded-sm ${color}`} />
            <span className="text-xs text-gray-500">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function MetricsDashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getMetrics(), listScans()])
      .then(([m, s]) => { setMetrics(m); setScans(s); })
      .catch(() => setError('Failed to load metrics.'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen px-4 py-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <BarChart2 className="w-6 h-6 text-indigo-400" />
          <h1 className="text-2xl font-bold">Analytics Dashboard</h1>
        </div>
        <div className="flex gap-3 flex-wrap">
          <Link to="/apps" className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Layers className="w-4 h-4" /> Portfolio
          </Link>
          <Link to="/compare" className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <GitCompare className="w-4 h-4" /> Compare
          </Link>
          <Link to="/scans" className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Shield className="w-4 h-4" /> History
          </Link>
          <Link to="/" className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Upload className="w-4 h-4" /> New Scan
          </Link>
        </div>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20 gap-2 text-gray-400">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading metrics…
        </div>
      )}

      {error && (
        <div className="bg-red-950 border border-red-700 rounded-xl p-4 text-red-300 text-sm">{error}</div>
      )}

      {!loading && !error && metrics && (
        <div className="space-y-6">

          {/* ── Overview KPIs ── */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <StatCard label="Total Scans" value={metrics.overview.totalScans.toLocaleString()} />
            <StatCard label="Scans Today" value={metrics.overview.scansToday} color="text-indigo-400" />
            <StatCard
              label="Detection Rate"
              value={`${(metrics.detectionRate * 100).toFixed(1)}%`}
              sub="PHA + suspicious / completed"
              color={metrics.detectionRate > 0.3 ? 'text-red-400' : 'text-green-400'}
            />
            <StatCard
              label="Error Rate"
              value={`${(metrics.overview.errorRate * 100).toFixed(1)}%`}
              color={metrics.overview.errorRate > 0.05 ? 'text-red-400' : 'text-green-400'}
            />
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <StatCard label="This Week" value={metrics.overview.scansThisWeek} sub="scans" />
            <StatCard label="This Month" value={metrics.overview.scansThisMonth} sub="scans" />
            <StatCard
              label="Avg Scan Time"
              value={metrics.overview.avgScanTimeMs != null
                ? `${(metrics.overview.avgScanTimeMs / 1000).toFixed(1)}s`
                : '—'}
              sub="completed scans"
              color="text-indigo-300"
            />
            <StatCard
              label="Avg Risk Score"
              value={metrics.overview.avgRiskScore != null
                ? metrics.overview.avgRiskScore.toFixed(1)
                : '—'}
              sub="0–100 scale"
              color={
                metrics.overview.avgRiskScore != null && metrics.overview.avgRiskScore >= 75
                  ? 'text-red-400'
                  : metrics.overview.avgRiskScore != null && metrics.overview.avgRiskScore >= 40
                  ? 'text-yellow-400'
                  : 'text-green-400'
              }
            />
          </div>

          {/* ── Scan Volume (30 days) ── */}
          <div className="bg-gray-900 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-indigo-400" />
              <h2 className="font-semibold text-sm">Scan Volume — Last 30 Days</h2>
            </div>
            <VolumeSpark data={metrics.scanVolumeByDay} />
          </div>

          {/* ── Threat Trend (30 days by verdict) ── */}
          <div className="bg-gray-900 rounded-xl p-5">
            <div className="flex items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                <h2 className="font-semibold text-sm">Threat Patterns — Last 30 Days</h2>
              </div>
              <span className="text-xs text-gray-600">stacked by verdict</span>
            </div>
            <ThreatTrendChart scans={scans} />
          </div>

          {/* ── Verdict breakdown + Risk buckets ── */}
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="bg-gray-900 rounded-xl p-5">
              <h2 className="font-semibold text-sm mb-4">Verdict Breakdown</h2>
              <div className="space-y-3">
                {(Object.keys(VERDICT_CFG) as (keyof typeof VERDICT_CFG)[]).map(v => {
                  const { label, cls, Icon } = VERDICT_CFG[v];
                  const count = metrics.verdictBreakdown[v] ?? 0;
                  const max = metrics.overview.totalScans;
                  const barColor = v === 'clean' ? 'bg-green-500' : v === 'pha' ? 'bg-red-500' : v === 'suspicious' ? 'bg-yellow-500' : 'bg-gray-600';
                  return (
                    <div key={v}>
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className={`w-3.5 h-3.5 ${cls}`} />
                        <span className="text-xs text-gray-300">{label}</span>
                      </div>
                      <SparkBar value={count} max={max} color={barColor} />
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="bg-gray-900 rounded-xl p-5">
              <h2 className="font-semibold text-sm mb-4">Risk Score Distribution</h2>
              <div className="space-y-3">
                {([
                  { key: 'low',      label: 'Low (0–25)',       color: 'bg-green-500' },
                  { key: 'moderate', label: 'Moderate (26–50)', color: 'bg-yellow-500' },
                  { key: 'high',     label: 'High (51–75)',     color: 'bg-orange-500' },
                  { key: 'critical', label: 'Critical (76–100)', color: 'bg-red-500' },
                ] as const).map(({ key, label, color }) => {
                  const dist = metrics.riskScoreDistribution;
                  const total = dist.low + dist.moderate + dist.high + dist.critical;
                  return (
                    <div key={key}>
                      <p className="text-xs text-gray-400 mb-1">{label}</p>
                      <SparkBar value={dist[key]} max={total} color={color} />
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* ── Top PHA categories + Findings by severity ── */}
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="bg-gray-900 rounded-xl p-5">
              <h2 className="font-semibold text-sm mb-4">Top PHA Categories</h2>
              {metrics.topPhaCategories.length === 0 ? (
                <p className="text-gray-600 text-sm">No PHA detections yet.</p>
              ) : (
                <div className="space-y-2">
                  {metrics.topPhaCategories.map(({ category, count }) => (
                    <div key={category}>
                      <p className="text-xs text-gray-400 capitalize mb-1">{category}</p>
                      <SparkBar
                        value={count}
                        max={metrics.topPhaCategories[0].count}
                        color="bg-red-500"
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="bg-gray-900 rounded-xl p-5">
              <h2 className="font-semibold text-sm mb-4">Findings by Severity</h2>
              <div className="space-y-2">
                {([
                  { key: 'critical', color: 'bg-red-500' },
                  { key: 'high',     color: 'bg-orange-500' },
                  { key: 'medium',   color: 'bg-yellow-500' },
                  { key: 'low',      color: 'bg-blue-500' },
                ] as const).map(({ key, color }) => {
                  const sev = metrics.findingsBySeverity;
                  const total = sev.critical + sev.high + sev.medium + sev.low;
                  return (
                    <div key={key}>
                      <p className="text-xs text-gray-400 capitalize mb-1">{key}</p>
                      <SparkBar value={sev[key] ?? 0} max={total} color={color} />
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* ── Top Rules ── */}
          {metrics.topRules.length > 0 && (
            <div className="bg-gray-900 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <Zap className="w-4 h-4 text-yellow-400" />
                <h2 className="font-semibold text-sm">Top Triggered Rules</h2>
              </div>
              <div className="space-y-2">
                {metrics.topRules.map(({ rule, count }) => (
                  <div key={rule}>
                    <p className="text-xs text-gray-400 font-mono mb-1">{rule}</p>
                    <SparkBar value={count} max={metrics.topRules[0].count} color="bg-indigo-500" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Privacy: Tracker Prevalence + Privacy Score Distribution ── */}
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="bg-gray-900 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <Eye className="w-4 h-4 text-purple-400" />
                <h2 className="font-semibold text-sm">Tracker SDK Prevalence</h2>
              </div>
              {metrics.trackerPrevalence.length === 0 ? (
                <p className="text-gray-600 text-sm">No tracker data yet.</p>
              ) : (
                <div className="space-y-2">
                  {metrics.trackerPrevalence.map(({ tracker, count }) => (
                    <div key={tracker}>
                      <p className="text-xs text-gray-400 mb-1">{tracker}</p>
                      <SparkBar value={count} max={metrics.trackerPrevalence[0].count} color="bg-purple-500" />
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="bg-gray-900 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <Eye className="w-4 h-4 text-purple-400" />
                <h2 className="font-semibold text-sm">Privacy Score Distribution</h2>
                {metrics.privacyScoreDistribution.avgScore != null && (
                  <span className="ml-auto text-xs text-purple-300 font-mono">
                    avg {metrics.privacyScoreDistribution.avgScore.toFixed(1)}
                  </span>
                )}
              </div>
              <div className="space-y-3">
                {([
                  { key: 'low',      label: 'Low (0–25)',        color: 'bg-green-500' },
                  { key: 'moderate', label: 'Moderate (26–50)',  color: 'bg-yellow-500' },
                  { key: 'high',     label: 'High (51–75)',      color: 'bg-orange-500' },
                  { key: 'critical', label: 'Critical (76–100)', color: 'bg-red-500' },
                ] as const).map(({ key, label, color }) => {
                  const dist = metrics.privacyScoreDistribution;
                  const total = dist.low + dist.moderate + dist.high + dist.critical;
                  return (
                    <div key={key}>
                      <p className="text-xs text-gray-400 mb-1">{label}</p>
                      <SparkBar value={dist[key]} max={total} color={color} />
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
