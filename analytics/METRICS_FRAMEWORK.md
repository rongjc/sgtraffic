# APK Scanner — Metrics & Analytics Framework

**Owner:** Data Analyst
**Last Updated:** 2026-03-13
**Status:** Implemented (v1)

---

## 1. What We Track and Why

This document describes the KPIs, SQL queries, and analytics architecture for the APK Malware Scanner. The goal is to give the team a clear, data-driven view of:

- Product health (are scans working reliably?)
- Security intelligence (what threats are we seeing?)
- User engagement (who is using the product and how?)
- Performance (how fast is the analyzer?)

---

## 2. KPI Definitions

### 2.1 Core Volume KPIs

| KPI | Definition | Target |
|-----|------------|--------|
| **Scans per day** | COUNT of scan rows with `created_at = today` | Growing week-over-week |
| **Scans this week** | COUNT of scans in the last 7 days | Baseline for growth |
| **Scans this month** | COUNT of scans in the last 30 days | Baseline for growth |

### 2.2 Quality & Reliability KPIs

| KPI | Definition | Target |
|-----|------------|--------|
| **Error rate** | `status = 'error'` / total scans | < 5% |
| **Avg scan time (ms)** | AVG of `(completed_at - created_at)` in ms for `status = 'done'` | < 30s |
| **Completion rate** | `status = 'done'` / total scans | > 95% |

### 2.3 Detection KPIs

| KPI | Definition | Target |
|-----|------------|--------|
| **Detection rate** | `(pha + suspicious)` / `(clean + pha + suspicious)` | Contextual |
| **Avg risk score** | AVG of `risk_score` for completed scans | Monitor for anomalies |
| **PHA category distribution** | Frequency of each category in `pha_categories` JSON | Security intelligence |
| **Most common rules** | Top rules triggered in `scan_findings` | Tune analyzer |
| **Severity distribution** | Finding counts by severity level | Prioritize response |

### 2.4 User / API Usage KPIs

| KPI | Definition | Target |
|-----|------------|--------|
| **Scans per user** | COUNT scans by `user_id` | Identify power users |
| **User retention** | Users active in last 7 days vs. 30 days | > 40% retention |

---

## 3. Data Schema Analysis

### 3.1 Current Schema

```sql
-- Users: who is submitting scans
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  api_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

-- Scans: one row per APK submitted
CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id),    -- nullable: anonymous scans
  filename TEXT NOT NULL,
  file_hash_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,                 -- pending | analyzing | done | error
  verdict TEXT NOT NULL,                -- clean | pha | suspicious | unknown
  pha_categories TEXT NOT NULL,         -- JSON array, e.g. ["spyware","ransomware"]
  risk_score INTEGER,                   -- 0-100, null if not completed
  error_message TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

-- Scan findings: individual rule hits within a scan
CREATE TABLE scan_findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,               -- critical | high | medium | low
  rule TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence TEXT
);
```

### 3.2 Recommended Schema Improvements (Future Work)

These additions would significantly improve analytics query performance and capability:

| Addition | Rationale |
|----------|-----------|
| `scans.scan_duration_ms INTEGER` | Denormalize scan time for fast AVG queries without datetime math |
| `scans.app_package_name TEXT` | Track which apps are scanned repeatedly; detect campaigns |
| `scans.analyzer_version TEXT` | Correlate detection rate changes to analyzer version upgrades |
| `INDEX ON scans(verdict)` | Speeds up verdict breakdown queries on large tables |
| `INDEX ON scans(date(created_at))` | Speeds up daily volume queries |
| `INDEX ON scan_findings(rule)` | Speeds up top-rules aggregation |

**Migration approach:** Add columns as nullable with defaults; backfill with `UPDATE` for existing rows where derivable.

---

## 4. SQL Query Reference

### 4.1 Scan Volume by Day (Last 30 Days)

```sql
SELECT date(created_at) AS date, COUNT(*) AS count
FROM scans
WHERE created_at >= datetime('now', '-30 days')
GROUP BY date(created_at)
ORDER BY date ASC;
```

### 4.2 Verdict Distribution

```sql
SELECT verdict, COUNT(*) AS count
FROM scans
GROUP BY verdict;
```

### 4.3 Detection Rate

```sql
SELECT
  ROUND(
    1.0 * SUM(CASE WHEN verdict IN ('pha','suspicious') THEN 1 ELSE 0 END)
    / NULLIF(SUM(CASE WHEN verdict != 'unknown' THEN 1 ELSE 0 END), 0),
    4
  ) AS detection_rate
FROM scans;
```

### 4.4 Most Common PHA Categories

```sql
-- SQLite JSON_EACH expansion
SELECT value AS category, COUNT(*) AS count
FROM scans, json_each(scans.pha_categories)
WHERE verdict IN ('pha', 'suspicious')
  AND pha_categories != '[]'
GROUP BY value
ORDER BY count DESC
LIMIT 10;
```

### 4.5 Average Scan Time (ms)

```sql
SELECT ROUND(AVG(
  (julianday(completed_at) - julianday(created_at)) * 86400000
), 0) AS avg_scan_time_ms
FROM scans
WHERE status = 'done'
  AND completed_at IS NOT NULL;
```

### 4.6 Top Triggered Rules

```sql
SELECT rule, COUNT(*) AS count
FROM scan_findings
GROUP BY rule
ORDER BY count DESC
LIMIT 10;
```

### 4.7 Findings by Severity

```sql
SELECT severity, COUNT(*) AS count
FROM scan_findings
GROUP BY severity;
```

### 4.8 Risk Score Distribution

```sql
SELECT
  SUM(CASE WHEN risk_score BETWEEN 0  AND 25  THEN 1 ELSE 0 END) AS low,
  SUM(CASE WHEN risk_score BETWEEN 26 AND 50  THEN 1 ELSE 0 END) AS moderate,
  SUM(CASE WHEN risk_score BETWEEN 51 AND 75  THEN 1 ELSE 0 END) AS high,
  SUM(CASE WHEN risk_score BETWEEN 76 AND 100 THEN 1 ELSE 0 END) AS critical
FROM scans
WHERE risk_score IS NOT NULL;
```

### 4.9 Error Rate

```sql
SELECT
  ROUND(1.0 * SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) / COUNT(*), 4)
    AS error_rate
FROM scans;
```

### 4.10 API Usage by User (Top 10)

```sql
SELECT user_id, COUNT(*) AS scan_count
FROM scans
GROUP BY user_id
ORDER BY scan_count DESC
LIMIT 10;
```

---

## 5. API Endpoint

### `GET /api/metrics`

Returns a single JSON object with all computed metrics. No authentication required in the MVP; add API key protection before exposing externally.

**Response shape:**

```json
{
  "overview": {
    "totalScans": 1250,
    "scansToday": 42,
    "scansThisWeek": 280,
    "scansThisMonth": 1100,
    "errorRate": 0.023,
    "avgScanTimeMs": 3200,
    "avgRiskScore": 34.5
  },
  "verdictBreakdown": { "clean": 820, "pha": 180, "suspicious": 200, "unknown": 50 },
  "detectionRate": 0.304,
  "scanVolumeByDay": [{ "date": "2026-03-01", "count": 45 }, "..."],
  "topPhaCategories": [{ "category": "spyware", "count": 80 }, "..."],
  "findingsBySeverity": { "critical": 45, "high": 120, "medium": 380, "low": 920 },
  "topRules": [{ "rule": "NETWORK_CLEAR_TEXT", "count": 230 }, "..."],
  "userActivity": [{ "user_id": "uuid", "scan_count": 145 }, "..."],
  "riskScoreDistribution": { "low": 600, "moderate": 300, "high": 150, "critical": 80 }
}
```

**Implementation:** `packages/api/src/routes/metrics.ts`

---

## 6. Dashboard

**Route:** `/metrics` (web app)
**Implementation:** `packages/web/src/pages/MetricsDashboardPage.tsx`

The dashboard renders all KPIs with:
- Overview stat cards (total scans, today, detection rate, error rate)
- 30-day scan volume sparkline
- Verdict breakdown bar chart
- Risk score distribution
- Top PHA categories
- Findings by severity
- Top triggered rules

No external charting library is required — SVG bars and CSS progress bars are used to keep the bundle lean.

---

## 7. What to Monitor (Alerts / SLA)

| Metric | Threshold | Action |
|--------|-----------|--------|
| Error rate | > 5% | Investigate analyzer health |
| Avg scan time | > 60s | Check analyzer queue depth and CPU |
| Detection rate drops > 10% | Sudden drop | May indicate analyzer version regression |
| Scans/day drops > 50% | Volume collapse | Check API uptime |

---

## 8. Future Improvements

1. **Time-based filtering** on the dashboard (7d / 30d / 90d toggle)
2. **Deduplicated hash tracking** — same APK rescanned should be flagged (already have `file_hash_sha256`)
3. **Retention cohorts** — weekly active users per signup cohort
4. **Analyzer version tracking** — add `analyzer_version` column, segment detection rate by version
5. **Export to CSV** — allow leadership to download raw reports
6. **Grafana integration** — expose `/api/metrics` as a Prometheus-compatible endpoint for ops dashboards
