/**
 * GET /api/metrics — analytics endpoint for APK Scanner dashboard.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { sql } from 'drizzle-orm';

const router = Router();

// GET /api/metrics
router.get('/', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();

    // ── Overview counts ────────────────────────────────────────────────────
    const overviewRow = db.get<{
      totalScans: number;
      scansToday: number;
      scansThisWeek: number;
      scansThisMonth: number;
      errorCount: number;
      avgRiskScore: number | null;
      avgScanTimeMs: number | null;
    }>(sql`
      SELECT
        COUNT(*) AS totalScans,
        SUM(CASE WHEN created_at >= ${todayStart} THEN 1 ELSE 0 END) AS scansToday,
        SUM(CASE WHEN created_at >= ${weekAgo} THEN 1 ELSE 0 END) AS scansThisWeek,
        SUM(CASE WHEN created_at >= ${monthAgo} THEN 1 ELSE 0 END) AS scansThisMonth,
        SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errorCount,
        AVG(risk_score) AS avgRiskScore,
        AVG(
          CASE
            WHEN completed_at IS NOT NULL AND completed_at != ''
            THEN (julianday(completed_at) - julianday(created_at)) * 86400000
            ELSE NULL
          END
        ) AS avgScanTimeMs
      FROM scans
    `);

    const totalScans = overviewRow?.totalScans ?? 0;
    const errorCount = overviewRow?.errorCount ?? 0;

    // ── Verdict breakdown ──────────────────────────────────────────────────
    const verdictRows = db.all<{ verdict: string; count: number }>(sql`
      SELECT verdict, COUNT(*) AS count FROM scans GROUP BY verdict
    `);

    const verdictBreakdown: Record<string, number> = { clean: 0, pha: 0, suspicious: 0, unknown: 0 };
    let detectedCount = 0;
    let completedCount = 0;
    for (const row of verdictRows) {
      verdictBreakdown[row.verdict] = row.count;
      if (row.verdict === 'pha' || row.verdict === 'suspicious') detectedCount += row.count;
      if (row.verdict !== 'unknown') completedCount += row.count;
    }
    const detectionRate = completedCount > 0
      ? Math.round((detectedCount / completedCount) * 10000) / 10000
      : 0;

    // ── Scan volume by day (last 30 days) ──────────────────────────────────
    const scanVolumeByDay = db.all<{ date: string; count: number }>(sql`
      SELECT substr(created_at, 1, 10) AS date, COUNT(*) AS count
      FROM scans
      WHERE created_at >= ${monthAgo}
      GROUP BY substr(created_at, 1, 10)
      ORDER BY date ASC
    `);

    // ── Top PHA categories (stored as JSON array in pha_categories) ────────
    const topPhaCategories = db.all<{ category: string; count: number }>(sql`
      SELECT value AS category, COUNT(*) AS count
      FROM scans, json_each(scans.pha_categories)
      WHERE verdict IN ('pha', 'suspicious')
        AND json_array_length(pha_categories) > 0
      GROUP BY value
      ORDER BY count DESC
      LIMIT 10
    `);

    // ── Findings by severity ───────────────────────────────────────────────
    const findingsBySeverityRows = db.all<{ severity: string; count: number }>(sql`
      SELECT severity, COUNT(*) AS count FROM scan_findings GROUP BY severity
    `);

    const findingsBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const row of findingsBySeverityRows) {
      findingsBySeverity[row.severity] = row.count;
    }

    // ── Top triggered rules ────────────────────────────────────────────────
    const topRules = db.all<{ rule: string; count: number }>(sql`
      SELECT rule, COUNT(*) AS count
      FROM scan_findings
      GROUP BY rule
      ORDER BY count DESC
      LIMIT 10
    `);

    // ── User activity ──────────────────────────────────────────────────────
    const userActivity = db.all<{ user_id: string | null; scan_count: number }>(sql`
      SELECT user_id, COUNT(*) AS scan_count
      FROM scans
      GROUP BY user_id
      ORDER BY scan_count DESC
      LIMIT 10
    `);

    // ── Risk score distribution ────────────────────────────────────────────
    const riskRow = db.get<{
      low: number; moderate: number; high: number; critical: number;
    }>(sql`
      SELECT
        SUM(CASE WHEN risk_score BETWEEN 0 AND 25 THEN 1 ELSE 0 END) AS low,
        SUM(CASE WHEN risk_score BETWEEN 26 AND 50 THEN 1 ELSE 0 END) AS moderate,
        SUM(CASE WHEN risk_score BETWEEN 51 AND 75 THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN risk_score BETWEEN 76 AND 100 THEN 1 ELSE 0 END) AS critical
      FROM scans
      WHERE risk_score IS NOT NULL
    `);

    res.json({
      overview: {
        totalScans,
        scansToday: overviewRow?.scansToday ?? 0,
        scansThisWeek: overviewRow?.scansThisWeek ?? 0,
        scansThisMonth: overviewRow?.scansThisMonth ?? 0,
        errorRate: totalScans > 0 ? Math.round((errorCount / totalScans) * 10000) / 10000 : 0,
        avgScanTimeMs: overviewRow?.avgScanTimeMs ?? null,
        avgRiskScore: overviewRow?.avgRiskScore ?? null,
      },
      verdictBreakdown,
      detectionRate,
      scanVolumeByDay,
      topPhaCategories,
      findingsBySeverity,
      topRules,
      userActivity,
      riskScoreDistribution: {
        low: riskRow?.low ?? 0,
        moderate: riskRow?.moderate ?? 0,
        high: riskRow?.high ?? 0,
        critical: riskRow?.critical ?? 0,
      },
      // trackerPrevalence and privacyScoreDistribution not yet in schema
      trackerPrevalence: [],
      privacyScoreDistribution: { low: 0, moderate: 0, high: 0, critical: 0, avgScore: null },
    });
  } catch (err) {
    next(err);
  }
});

export default router;
