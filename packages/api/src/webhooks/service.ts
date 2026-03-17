/**
 * Webhook delivery service.
 * Handles dispatch, HMAC-SHA256 signing, and retry logic (up to 3 attempts with exponential backoff).
 */

import crypto from 'crypto';
import { db } from '../db';
import { webhooks, webhookDeliveries, scans } from '../db/schema';
import { eq, and, lte, inArray } from 'drizzle-orm';

export type WebhookEventType = 'scan.completed' | 'scan.failed';

export interface WebhookPayload {
  event: WebhookEventType;
  scanId: string;
  apkHash: string;
  threatScore: number | null;
  detectedThreats: string[];
  scanDuration: number | null; // milliseconds
  timestamp: string;
}

// Retry delays in milliseconds: 30s, 60s, 120s
const RETRY_DELAYS_MS = [30_000, 60_000, 120_000];
const MAX_ATTEMPTS = 3;
const DELIVERY_TIMEOUT_MS = 10_000;

export function buildPayload(
  eventType: WebhookEventType,
  scan: typeof scans.$inferSelect,
): WebhookPayload {
  const createdAt = new Date(scan.createdAt + 'Z').getTime();
  const completedAt = scan.completedAt ? new Date(scan.completedAt + 'Z').getTime() : null;
  const scanDuration = completedAt ? completedAt - createdAt : null;

  return {
    event: eventType,
    scanId: scan.id,
    apkHash: scan.fileHashSha256,
    threatScore: scan.riskScore ?? null,
    detectedThreats: JSON.parse(scan.phaCategories ?? '[]') as string[],
    scanDuration,
    timestamp: new Date().toISOString(),
  };
}

export function signPayload(payloadJson: string, secret: string): string {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(payloadJson).digest('hex');
}

/**
 * Find all enabled webhooks subscribed to the given event type and create
 * delivery records, then attempt immediate delivery for each.
 */
export async function dispatchWebhooks(
  eventType: WebhookEventType,
  scan: typeof scans.$inferSelect,
): Promise<void> {
  const allWebhooks = db
    .select()
    .from(webhooks)
    .where(eq(webhooks.enabled, true))
    .all();

  const subscribed = allWebhooks.filter((wh) => {
    try {
      const types = JSON.parse(wh.eventTypes) as string[];
      return types.includes(eventType);
    } catch {
      return false;
    }
  });

  if (subscribed.length === 0) return;

  const payload = buildPayload(eventType, scan);
  const payloadJson = JSON.stringify(payload);

  for (const wh of subscribed) {
    const deliveryId = crypto.randomUUID();
    db.insert(webhookDeliveries)
      .values({
        id: deliveryId,
        webhookId: wh.id,
        scanId: scan.id,
        eventType,
        payload: payloadJson,
        status: 'pending',
        attempts: 0,
      })
      .run();

    // Fire-and-forget; errors are recorded in the delivery record
    void attemptDelivery(wh, deliveryId, payloadJson);
  }
}

/**
 * Attempt delivery for a single webhook delivery record.
 * Updates the delivery record with the result.
 */
export async function attemptDelivery(
  wh: typeof webhooks.$inferSelect,
  deliveryId: string,
  payloadJson: string,
): Promise<void> {
  const delivery = db
    .select()
    .from(webhookDeliveries)
    .where(eq(webhookDeliveries.id, deliveryId))
    .get();

  if (!delivery) return;

  const attempts = delivery.attempts + 1;
  const signature = signPayload(payloadJson, wh.signingSecret);

  let responseCode: number | null = null;
  let responseBody: string | null = null;
  let success = false;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

    const response = await fetch(wh.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Signature': signature,
        'X-Webhook-Event': delivery.eventType,
        'X-Webhook-Delivery': deliveryId,
      },
      body: payloadJson,
      signal: controller.signal,
    });

    clearTimeout(timer);
    responseCode = response.status;
    responseBody = (await response.text()).slice(0, 1000); // cap at 1KB
    success = response.ok;
  } catch (err) {
    responseBody = err instanceof Error ? err.message : String(err);
  }

  if (success) {
    db.update(webhookDeliveries)
      .set({
        status: 'delivered',
        responseCode,
        responseBody,
        attempts,
        deliveredAt: new Date().toISOString(),
        nextRetryAt: null,
      })
      .where(eq(webhookDeliveries.id, deliveryId))
      .run();

    console.log(`[Webhook] Delivered ${delivery.eventType} to ${wh.url} (delivery=${deliveryId})`);
    return;
  }

  // Failed — schedule retry or mark permanent failure
  const nextRetryDelay = RETRY_DELAYS_MS[attempts - 1]; // undefined when attempts >= MAX_ATTEMPTS
  const permanentFailure = attempts >= MAX_ATTEMPTS || nextRetryDelay === undefined;

  const nextRetryAt = permanentFailure
    ? null
    : new Date(Date.now() + nextRetryDelay).toISOString();

  db.update(webhookDeliveries)
    .set({
      status: permanentFailure ? 'failed' : 'pending',
      responseCode,
      responseBody,
      attempts,
      nextRetryAt,
    })
    .where(eq(webhookDeliveries.id, deliveryId))
    .run();

  console.warn(
    `[Webhook] Delivery failed for ${delivery.eventType} to ${wh.url} ` +
      `(attempt ${attempts}/${MAX_ATTEMPTS}, delivery=${deliveryId})` +
      (permanentFailure ? ' — permanent failure' : ` — retry at ${nextRetryAt}`),
  );
}

/**
 * Poll for pending deliveries whose nextRetryAt has passed and retry them.
 * Called by the background retry interval.
 */
export async function retryPendingDeliveries(): Promise<void> {
  const now = new Date().toISOString();

  const pending = db
    .select()
    .from(webhookDeliveries)
    .where(
      and(
        eq(webhookDeliveries.status, 'pending'),
        lte(webhookDeliveries.nextRetryAt, now),
      ),
    )
    .all();

  if (pending.length === 0) return;

  const webhookIds = [...new Set(pending.map((d) => d.webhookId))];
  const whRows = db
    .select()
    .from(webhooks)
    .where(inArray(webhooks.id, webhookIds))
    .all();

  const whMap = new Map(whRows.map((wh) => [wh.id, wh]));

  for (const delivery of pending) {
    const wh = whMap.get(delivery.webhookId);
    if (!wh || !wh.enabled) continue;
    void attemptDelivery(wh, delivery.id, delivery.payload);
  }
}

/**
 * Start the background retry loop. Returns a cleanup function.
 */
export function startWebhookRetryLoop(): () => void {
  const interval = setInterval(() => {
    void retryPendingDeliveries();
  }, 30_000);

  return () => clearInterval(interval);
}
