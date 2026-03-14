/**
 * Periodic cleanup for scans stuck in 'pending' or 'analyzing' state.
 * Scans older than STUCK_THRESHOLD_MINUTES that never completed are marked as error.
 */

import { and, inArray, lt } from 'drizzle-orm';
import { db } from '../db';
import { scans } from '../db/schema';

const STUCK_THRESHOLD_MINUTES = parseInt(process.env.STUCK_SCAN_TIMEOUT_MINUTES ?? '30', 10);
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // run every 5 minutes

export function startStaleScanCleanup(): void {
  const runCleanup = () => {
    try {
      const cutoff = new Date(Date.now() - STUCK_THRESHOLD_MINUTES * 60 * 1000).toISOString();
      const result = db
        .update(scans)
        .set({
          status: 'error',
          errorMessage: `Scan timed out: still pending after ${STUCK_THRESHOLD_MINUTES} minutes`,
          completedAt: new Date().toISOString(),
        })
        .where(and(inArray(scans.status, ['pending', 'analyzing']), lt(scans.createdAt, cutoff)))
        .run();

      if (result.changes > 0) {
        console.log(`[Cleanup] Marked ${result.changes} stale scan(s) as error`);
      }
    } catch (err) {
      console.error('[Cleanup] Error during stale scan cleanup:', err);
    }
  };

  // Run immediately on startup to catch any scans orphaned by a previous server restart
  runCleanup();
  setInterval(runCleanup, CLEANUP_INTERVAL_MS);

  console.log(
    `[Cleanup] Stale scan cleanup started (threshold: ${STUCK_THRESHOLD_MINUTES}min, interval: ${CLEANUP_INTERVAL_MS / 60000}min)`,
  );
}
