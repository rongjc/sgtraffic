/**
 * Simple in-process job queue for APK analysis.
 * Processes one APK at a time. Retries once on failure. 5-min timeout.
 */

interface Job {
  scanId: string;
  filePath: string;
}

type JobProcessor = (job: Job) => Promise<void>;

const TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const MAX_RETRIES = 1;

class SimpleJobQueue {
  private queue: Job[] = [];
  private processing = false;
  private processor: JobProcessor | null = null;

  register(processor: JobProcessor) {
    this.processor = processor;
  }

  enqueue(job: Job) {
    this.queue.push(job);
    if (!this.processing) {
      void this.drain();
    }
  }

  private async drain() {
    if (this.processing || !this.processor) return;
    this.processing = true;

    while (this.queue.length > 0) {
      const job = this.queue.shift()!;
      try {
        await this.runWithRetry(job);
      } catch (err) {
        // Permanent failure already logged in runWithRetry; continue draining
        console.error(`[Queue] Continuing after permanent failure for job ${job.scanId}`);
      }
    }

    this.processing = false;
  }

  private async runWithRetry(job: Job, attempt = 0) {
    try {
      await Promise.race([
        this.processor!(job),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Job timed out after 5 minutes')), TIMEOUT_MS),
        ),
      ]);
    } catch (err) {
      if (attempt < MAX_RETRIES) {
        console.warn(`[Queue] Job ${job.scanId} failed (attempt ${attempt + 1}), retrying...`);
        await this.runWithRetry(job, attempt + 1);
      } else {
        console.error(`[Queue] Job ${job.scanId} failed permanently:`, err);
        // Caller (processor registration) should handle marking the scan as error
        throw err;
      }
    }
  }
}

export const jobQueue = new SimpleJobQueue();
