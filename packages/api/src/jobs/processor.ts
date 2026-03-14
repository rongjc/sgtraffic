/**
 * APK analysis job processor.
 * Calls the Python analyzer HTTP endpoint, parses results,
 * and updates the scan record + findings in the database.
 */

import crypto from 'crypto';
import fs from 'fs';
import { db } from '../db';
import { scans, scanFindings } from '../db/schema';
import { eq } from 'drizzle-orm';

function deleteApkFile(filePath: string): void {
  fs.unlink(filePath, (err) => {
    if (err && err.code !== 'ENOENT') {
      console.warn(`[Processor] Failed to delete APK file ${filePath}:`, err.message);
    }
  });
}

const ANALYZER_URL = process.env.ANALYZER_URL ?? 'http://127.0.0.1:5001';

interface AnalyzerFinding {
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  rule: string;
  description: string;
  evidence?: string;
}

interface AnalyzerResult {
  verdict: 'clean' | 'pha' | 'suspicious';
  risk_score: number;
  pha_categories: string[];
  findings: AnalyzerFinding[];
  metadata: Record<string, unknown>;
}

export async function processApkJob(job: { scanId: string; filePath: string }): Promise<void> {
  const { scanId, filePath } = job;

  // Mark as analyzing
  db.update(scans)
    .set({ status: 'analyzing' })
    .where(eq(scans.id, scanId))
    .run();

  console.log(`[Processor] Starting analysis for scan ${scanId}: ${filePath}`);

  let result: AnalyzerResult;
  try {
    const response = await fetch(`${ANALYZER_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apk_path: filePath }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Analyzer returned HTTP ${response.status}: ${body}`);
    }

    result = (await response.json()) as AnalyzerResult;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[Processor] Analyzer call failed for scan ${scanId}:`, msg);

    db.update(scans)
      .set({
        status: 'error',
        errorMessage: msg,
        completedAt: new Date().toISOString(),
      })
      .where(eq(scans.id, scanId))
      .run();

    deleteApkFile(filePath);
    throw err; // rethrow so the queue can retry
  }

  // Insert individual findings
  for (const f of result.findings) {
    db.insert(scanFindings)
      .values({
        id: crypto.randomUUID(),
        scanId,
        category: f.category,
        severity: f.severity,
        rule: f.rule,
        description: f.description,
        evidence: f.evidence ?? null,
      })
      .run();
  }

  // Update scan record with final results
  db.update(scans)
    .set({
      status: 'done',
      verdict: result.verdict,
      riskScore: result.risk_score,
      phaCategories: JSON.stringify(result.pha_categories),
      completedAt: new Date().toISOString(),
    })
    .where(eq(scans.id, scanId))
    .run();

  deleteApkFile(filePath);
  console.log(
    `[Processor] Scan ${scanId} complete: verdict=${result.verdict} risk=${result.risk_score} findings=${result.findings.length}`,
  );
}
