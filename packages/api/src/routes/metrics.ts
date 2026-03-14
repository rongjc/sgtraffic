/**
 * GET /api/metrics — analytics endpoint for APK Scanner dashboard.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { getDb } from '../db';

const router = Router();

// GET /api/metrics
router.get('/', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const db = getDb();
    const scansCol = db.collection('scans');
    const findingsCol = db.collection('scan_findings');

    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();

    // ── Overview counts ────────────────────────────────────────────────────
    const overviewPipeline = [
      {
        $group: {
          _id: null,
          totalScans: { $sum: 1 },
          scansToday: { $sum: { $cond: [{ $gte: ['$createdAt', todayStart] }, 1, 0] } },
          scansThisWeek: { $sum: { $cond: [{ $gte: ['$createdAt', weekAgo] }, 1, 0] } },
          scansThisMonth: { $sum: { $cond: [{ $gte: ['$createdAt', monthAgo] }, 1, 0] } },
          errorCount: { $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] } },
          avgRiskScore: { $avg: '$riskScore' },
          avgScanTimeMs: {
            $avg: {
              $cond: [
                { $and: [{ $ne: ['$completedAt', null] }, { $ne: ['$completedAt', ''] }] },
                {
                  $subtract: [
                    { $toDate: '$completedAt' },
                    { $toDate: '$createdAt' },
                  ],
                },
                null,
              ],
            },
          },
        },
      },
    ];
    const overviewResult = await scansCol.aggregate(overviewPipeline).toArray();
    const ov = overviewResult[0] ?? {};
    const totalScans: number = ov.totalScans ?? 0;
    const errorCount: number = ov.errorCount ?? 0;

    // ── Verdict breakdown ──────────────────────────────────────────────────
    const verdictRows = await scansCol
      .aggregate([{ $group: { _id: '$verdict', count: { $sum: 1 } } }])
      .toArray();

    const verdictBreakdown: Record<string, number> = { clean: 0, pha: 0, suspicious: 0, unknown: 0 };
    let detectedCount = 0;
    let completedCount = 0;
    for (const row of verdictRows) {
      verdictBreakdown[row._id as string] = row.count as number;
      if (row._id === 'pha' || row._id === 'suspicious') detectedCount += row.count as number;
      if (row._id !== 'unknown') completedCount += row.count as number;
    }
    const detectionRate =
      completedCount > 0 ? Math.round((detectedCount / completedCount) * 10000) / 10000 : 0;

    // ── Scan volume by day (last 30 days) ──────────────────────────────────
    const scanVolumeByDay = await scansCol
      .aggregate([
        { $match: { createdAt: { $gte: monthAgo } } },
        {
          $group: {
            _id: { $substr: ['$createdAt', 0, 10] }, // YYYY-MM-DD
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
        { $project: { _id: 0, date: '$_id', count: 1 } },
      ])
      .toArray();

    // ── Top PHA categories ─────────────────────────────────────────────────
    const topPhaCategories = await scansCol
      .aggregate([
        { $match: { verdict: { $in: ['pha', 'suspicious'] }, phaCategories: { $ne: [] } } },
        { $unwind: '$phaCategories' },
        { $group: { _id: '$phaCategories', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
        { $project: { _id: 0, category: '$_id', count: 1 } },
      ])
      .toArray();

    // ── Findings by severity ───────────────────────────────────────────────
    const findingsBySeverityRows = await findingsCol
      .aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }])
      .toArray();

    const findingsBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const row of findingsBySeverityRows) {
      findingsBySeverity[row._id as string] = row.count as number;
    }

    // ── Top triggered rules ────────────────────────────────────────────────
    const topRules = await findingsCol
      .aggregate([
        { $group: { _id: '$rule', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
        { $project: { _id: 0, rule: '$_id', count: 1 } },
      ])
      .toArray();

    // ── Tracker prevalence (from privacy analysis) ─────────────────────────
    const trackerPrevalence = await scansCol
      .aggregate([
        { $match: { trackersDetected: { $exists: true, $ne: null, $not: { $size: 0 } } } },
        { $unwind: '$trackersDetected' },
        { $group: { _id: '$trackersDetected', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 },
        { $project: { _id: 0, tracker: '$_id', count: 1 } },
      ])
      .toArray();

    // ── Privacy score distribution ─────────────────────────────────────────
    const privacyBucketsPipeline = [
      { $match: { privacyScore: { $ne: null } } },
      {
        $group: {
          _id: null,
          low:      { $sum: { $cond: [{ $and: [{ $gte: ['$privacyScore', 0] },  { $lte: ['$privacyScore', 25] }] }, 1, 0] } },
          moderate: { $sum: { $cond: [{ $and: [{ $gte: ['$privacyScore', 26] }, { $lte: ['$privacyScore', 50] }] }, 1, 0] } },
          high:     { $sum: { $cond: [{ $and: [{ $gte: ['$privacyScore', 51] }, { $lte: ['$privacyScore', 75] }] }, 1, 0] } },
          critical: { $sum: { $cond: [{ $and: [{ $gte: ['$privacyScore', 76] }, { $lte: ['$privacyScore', 100] }] }, 1, 0] } },
          avgScore: { $avg: '$privacyScore' },
        },
      },
    ];
    const privacyBucketsResult = await scansCol.aggregate(privacyBucketsPipeline).toArray();
    const pb = privacyBucketsResult[0] ?? {};

    // ── User activity ──────────────────────────────────────────────────────
    const userActivity = await scansCol
      .aggregate([
        { $group: { _id: '$userId', scan_count: { $sum: 1 } } },
        { $sort: { scan_count: -1 } },
        { $limit: 10 },
        { $project: { _id: 0, user_id: '$_id', scan_count: 1 } },
      ])
      .toArray();

    // ── Risk score distribution ────────────────────────────────────────────
    const riskBucketsPipeline = [
      { $match: { riskScore: { $ne: null } } },
      {
        $group: {
          _id: null,
          low: { $sum: { $cond: [{ $and: [{ $gte: ['$riskScore', 0] }, { $lte: ['$riskScore', 25] }] }, 1, 0] } },
          moderate: { $sum: { $cond: [{ $and: [{ $gte: ['$riskScore', 26] }, { $lte: ['$riskScore', 50] }] }, 1, 0] } },
          high: { $sum: { $cond: [{ $and: [{ $gte: ['$riskScore', 51] }, { $lte: ['$riskScore', 75] }] }, 1, 0] } },
          critical: { $sum: { $cond: [{ $and: [{ $gte: ['$riskScore', 76] }, { $lte: ['$riskScore', 100] }] }, 1, 0] } },
        },
      },
    ];
    const riskBucketsResult = await scansCol.aggregate(riskBucketsPipeline).toArray();
    const rb = riskBucketsResult[0] ?? {};

    res.json({
      overview: {
        totalScans,
        scansToday: ov.scansToday ?? 0,
        scansThisWeek: ov.scansThisWeek ?? 0,
        scansThisMonth: ov.scansThisMonth ?? 0,
        errorRate: totalScans > 0 ? Math.round((errorCount / totalScans) * 10000) / 10000 : 0,
        avgScanTimeMs: ov.avgScanTimeMs ?? null,
        avgRiskScore: ov.avgRiskScore ?? null,
      },
      verdictBreakdown,
      detectionRate,
      scanVolumeByDay,
      topPhaCategories,
      findingsBySeverity,
      topRules,
      userActivity,
      riskScoreDistribution: {
        low: rb.low ?? 0,
        moderate: rb.moderate ?? 0,
        high: rb.high ?? 0,
        critical: rb.critical ?? 0,
      },
      trackerPrevalence,
      privacyScoreDistribution: {
        low: pb.low ?? 0,
        moderate: pb.moderate ?? 0,
        high: pb.high ?? 0,
        critical: pb.critical ?? 0,
        avgScore: pb.avgScore ?? null,
      },
    });
  } catch (err) {
    next(err);
  }
});

export default router;
