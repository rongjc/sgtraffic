/**
 * Webhook CRUD routes.
 *
 * POST   /api/webhooks              — register a webhook
 * GET    /api/webhooks              — list webhooks
 * GET    /api/webhooks/:id          — get single webhook
 * PATCH  /api/webhooks/:id          — update (url, eventTypes, enabled)
 * DELETE /api/webhooks/:id          — delete webhook
 * GET    /api/webhooks/:id/deliveries — delivery history
 * POST   /api/webhooks/:id/test     — send a test ping
 */

import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { db } from '../db';
import { webhooks, webhookDeliveries } from '../db/schema';
import { eq, desc } from 'drizzle-orm';
import { signPayload, attemptDelivery } from '../webhooks/service';

const router = Router();

const VALID_EVENT_TYPES = ['scan.completed', 'scan.failed'];

function isHttpsUrl(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

// POST /api/webhooks — register
router.post('/', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { url, eventTypes } = req.body as { url?: unknown; eventTypes?: unknown };

    if (typeof url !== 'string' || !url.trim()) {
      res.status(400).json({ error: 'url is required' });
      return;
    }

    if (!isHttpsUrl(url)) {
      res.status(400).json({ error: 'url must use HTTPS' });
      return;
    }

    const events: string[] = Array.isArray(eventTypes) ? eventTypes : VALID_EVENT_TYPES;
    const invalid = events.filter((e) => !VALID_EVENT_TYPES.includes(e));
    if (invalid.length > 0) {
      res.status(400).json({ error: `Invalid event types: ${invalid.join(', ')}` });
      return;
    }

    const id = crypto.randomUUID();
    const signingSecret = crypto.randomBytes(32).toString('hex');

    db.insert(webhooks)
      .values({
        id,
        url,
        eventTypes: JSON.stringify(events),
        signingSecret,
        enabled: true,
      })
      .run();

    // Send an immediate test ping (fire-and-forget)
    const wh = db.select().from(webhooks).where(eq(webhooks.id, id)).get()!;
    const pingPayload = JSON.stringify({ event: 'ping', webhookId: id, timestamp: new Date().toISOString() });
    const pingDeliveryId = crypto.randomUUID();
    db.insert(webhookDeliveries)
      .values({
        id: pingDeliveryId,
        webhookId: id,
        eventType: 'ping',
        payload: pingPayload,
        status: 'pending',
        attempts: 0,
      })
      .run();
    void attemptDelivery(wh, pingDeliveryId, pingPayload);

    res.status(201).json({
      id,
      url,
      eventTypes: events,
      signingSecret,
      enabled: true,
      createdAt: wh.createdAt,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/webhooks — list
router.get('/', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const rows = db.select().from(webhooks).all();
    res.json(rows.map(formatWebhook));
  } catch (err) {
    next(err);
  }
});

// GET /api/webhooks/:id — single
router.get('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const row = db.select().from(webhooks).where(eq(webhooks.id, req.params.id)).get();
    if (!row) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }
    res.json(formatWebhook(row));
  } catch (err) {
    next(err);
  }
});

// PATCH /api/webhooks/:id — update
router.patch('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const row = db.select().from(webhooks).where(eq(webhooks.id, req.params.id)).get();
    if (!row) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }

    const { url, eventTypes, enabled } = req.body as {
      url?: unknown;
      eventTypes?: unknown;
      enabled?: unknown;
    };

    const updates: Partial<typeof webhooks.$inferInsert> = {};

    if (url !== undefined) {
      if (typeof url !== 'string' || !isHttpsUrl(url)) {
        res.status(400).json({ error: 'url must be a valid HTTPS URL' });
        return;
      }
      updates.url = url;
    }

    if (eventTypes !== undefined) {
      if (!Array.isArray(eventTypes)) {
        res.status(400).json({ error: 'eventTypes must be an array' });
        return;
      }
      const invalid = eventTypes.filter((e) => !VALID_EVENT_TYPES.includes(e));
      if (invalid.length > 0) {
        res.status(400).json({ error: `Invalid event types: ${invalid.join(', ')}` });
        return;
      }
      updates.eventTypes = JSON.stringify(eventTypes);
    }

    if (enabled !== undefined) {
      if (typeof enabled !== 'boolean') {
        res.status(400).json({ error: 'enabled must be a boolean' });
        return;
      }
      updates.enabled = enabled;
    }

    if (Object.keys(updates).length === 0) {
      res.status(400).json({ error: 'No valid fields to update' });
      return;
    }

    db.update(webhooks).set(updates).where(eq(webhooks.id, req.params.id)).run();

    const updated = db.select().from(webhooks).where(eq(webhooks.id, req.params.id)).get()!;
    res.json(formatWebhook(updated));
  } catch (err) {
    next(err);
  }
});

// DELETE /api/webhooks/:id
router.delete('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const row = db.select().from(webhooks).where(eq(webhooks.id, req.params.id)).get();
    if (!row) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }
    db.delete(webhooks).where(eq(webhooks.id, req.params.id)).run();
    res.status(204).send();
  } catch (err) {
    next(err);
  }
});

// GET /api/webhooks/:id/deliveries — delivery log
router.get('/:id/deliveries', (req: Request, res: Response, next: NextFunction) => {
  try {
    const row = db.select().from(webhooks).where(eq(webhooks.id, req.params.id)).get();
    if (!row) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }

    const deliveries = db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.webhookId, req.params.id))
      .orderBy(desc(webhookDeliveries.createdAt))
      .all();

    res.json(deliveries);
  } catch (err) {
    next(err);
  }
});

// POST /api/webhooks/:id/test — manual test ping
router.post('/:id/test', (req: Request, res: Response, next: NextFunction) => {
  try {
    const wh = db.select().from(webhooks).where(eq(webhooks.id, req.params.id)).get();
    if (!wh) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }

    const pingPayload = JSON.stringify({
      event: 'ping',
      webhookId: wh.id,
      timestamp: new Date().toISOString(),
    });
    const deliveryId = crypto.randomUUID();

    db.insert(webhookDeliveries)
      .values({
        id: deliveryId,
        webhookId: wh.id,
        eventType: 'ping',
        payload: pingPayload,
        status: 'pending',
        attempts: 0,
      })
      .run();

    void attemptDelivery(wh, deliveryId, pingPayload);

    res.json({ deliveryId, message: 'Test ping enqueued' });
  } catch (err) {
    next(err);
  }
});

function formatWebhook(row: typeof webhooks.$inferSelect) {
  return {
    ...row,
    eventTypes: JSON.parse(row.eventTypes ?? '[]') as string[],
    // Never expose signing secret in list; only returned at creation time
    signingSecret: undefined,
  };
}

export default router;
