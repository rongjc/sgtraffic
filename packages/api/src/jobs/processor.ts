/**
 * APK analysis job processor.
 * Calls the Python analyzer HTTP endpoint, parses results,
 * and updates the scan record + findings in the database.
 */

import crypto from 'crypto';
import fs from 'fs';
import { z } from 'zod';
import { db } from '../db';
import { scans, scanFindings } from '../db/schema';
import { eq } from 'drizzle-orm';
import { dispatchWebhooks } from '../webhooks/service';

function deleteApkFile(filePath: string): void {
  fs.unlink(filePath, (err) => {
    if (err && err.code !== 'ENOENT') {
      console.warn(`[Processor] Failed to delete APK file ${filePath}:`, err.message);
    }
  });
}

const ANALYZER_URL = process.env.ANALYZER_URL ?? 'http://127.0.0.1:5001';

const AnalyzerResultSchema = z.object({
  verdict: z.enum(['clean', 'pha', 'suspicious']),
  risk_score: z.number().int().min(0).max(100),
  pha_categories: z.array(z.string()),
  findings: z.array(
    z.object({
      category: z.string(),
      severity: z.enum(['critical', 'high', 'medium', 'low']),
      rule: z.string(),
      description: z.string(),
      evidence: z.string().optional(),
    }),
  ),
  metadata: z.record(z.unknown()),
});

type AnalyzerResult = z.infer<typeof AnalyzerResultSchema>;

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

    const raw = await response.json();
    const parsed = AnalyzerResultSchema.safeParse(raw);
    if (!parsed.success) {
      throw new Error(`Analyzer response validation failed: ${parsed.error.message}`);
    }
    result = parsed.data;
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

    // Dispatch scan.failed webhooks (fire-and-forget)
    const failedScan = db.select().from(scans).where(eq(scans.id, scanId)).get();
    if (failedScan) {
      void dispatchWebhooks('scan.failed', failedScan);
    }

    deleteApkFile(filePath);
    throw err; // rethrow so the queue can retry
  }

  // Batch insert all findings in a single statement
  if (result.findings.length > 0) {
    db.insert(scanFindings)
      .values(
        result.findings.map((f) => ({
          id: crypto.randomUUID(),
          scanId,
          category: f.category,
          severity: f.severity,
          rule: f.rule,
          description: f.description,
          evidence: f.evidence ?? null,
        })),
      )
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

  // Dispatch scan.completed webhooks (fire-and-forget)
  const completedScan = db.select().from(scans).where(eq(scans.id, scanId)).get();
  if (completedScan) {
    void dispatchWebhooks('scan.completed', completedScan);
  }
}
