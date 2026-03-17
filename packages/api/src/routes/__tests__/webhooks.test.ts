/**
 * Integration tests for /api/webhooks
 * Mocks the db module and webhook service to avoid native bindings.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { errorHandler, notFound } from '../../middleware/errorHandler';

// --- Hoisted mocks ---
const { mockDb, mockWebhookRow } = vi.hoisted(() => {
  const mockWebhookRow = {
    id: 'wh-123',
    url: 'https://example.com/hook',
    eventTypes: '["scan.completed","scan.failed"]',
    signingSecret: 'secret-abc',
    enabled: true,
    userId: null,
    createdAt: '2026-01-01T00:00:00.000Z',
  };

  function makeChain(result: unknown) {
    return {
      from: vi.fn().mockReturnThis(),
      values: vi.fn().mockReturnThis(),
      set: vi.fn().mockReturnThis(),
      where: vi.fn().mockReturnThis(),
      orderBy: vi.fn().mockReturnThis(),
      all: vi.fn().mockReturnValue(result),
      get: vi.fn().mockReturnValue(result),
      run: vi.fn().mockReturnValue(undefined),
    };
  }

  const mockDb = {
    select: vi.fn(),
    insert: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    _makeChain: makeChain,
  };

  return { mockDb, mockWebhookRow };
});

vi.mock('../../db', () => ({ db: mockDb, initDb: vi.fn() }));

vi.mock('../../webhooks/service', () => ({
  attemptDelivery: vi.fn().mockResolvedValue(undefined),
  signPayload: vi.fn().mockReturnValue('sha256=abc'),
  dispatchWebhooks: vi.fn().mockResolvedValue(undefined),
  startWebhookRetryLoop: vi.fn().mockReturnValue(() => {}),
}));

import webhooksRouter from '../webhooks';

const app = express();
app.use(express.json());
app.use('/api/webhooks', webhooksRouter);
app.use(notFound);
app.use(errorHandler);

beforeEach(() => {
  vi.clearAllMocks();

  // Default select chain returns the stub webhook
  mockDb.select.mockImplementation(() => mockDb._makeChain(mockWebhookRow));
  mockDb.insert.mockImplementation(() => mockDb._makeChain(undefined));
  mockDb.update.mockImplementation(() => mockDb._makeChain(undefined));
  mockDb.delete.mockImplementation(() => mockDb._makeChain(undefined));
});

describe('POST /api/webhooks', () => {
  it('returns 400 when url is missing', async () => {
    const res = await request(app).post('/api/webhooks').send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/url is required/i);
  });

  it('returns 400 when url is not HTTPS', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ url: 'http://example.com/hook' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/https/i);
  });

  it('returns 400 for invalid event types', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://example.com/hook', eventTypes: ['invalid.event'] });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid event types/i);
  });

  it('creates webhook and returns 201 with signingSecret', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://example.com/hook', eventTypes: ['scan.completed'] });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      url: 'https://example.com/hook',
      eventTypes: ['scan.completed'],
      enabled: true,
    });
    // signing secret must be present on creation
    expect(typeof res.body.signingSecret).toBe('string');
    expect(res.body.signingSecret.length).toBeGreaterThan(0);
  });

  it('defaults eventTypes to both event types when omitted', async () => {
    const res = await request(app)
      .post('/api/webhooks')
      .send({ url: 'https://example.com/hook' });

    expect(res.status).toBe(201);
    expect(res.body.eventTypes).toEqual(['scan.completed', 'scan.failed']);
  });
});

describe('GET /api/webhooks', () => {
  it('returns list of webhooks without signingSecret', async () => {
    mockDb.select.mockImplementation(() => mockDb._makeChain([mockWebhookRow]));
    const res = await request(app).get('/api/webhooks');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0].signingSecret).toBeUndefined();
    expect(res.body[0].eventTypes).toEqual(['scan.completed', 'scan.failed']);
  });
});

describe('GET /api/webhooks/:id', () => {
  it('returns 404 for unknown webhook', async () => {
    mockDb.select.mockImplementation(() => mockDb._makeChain(null));
    const res = await request(app).get('/api/webhooks/nonexistent');
    expect(res.status).toBe(404);
  });

  it('returns webhook without signingSecret', async () => {
    const res = await request(app).get('/api/webhooks/wh-123');
    expect(res.status).toBe(200);
    expect(res.body.id).toBe('wh-123');
    expect(res.body.signingSecret).toBeUndefined();
  });
});

describe('PATCH /api/webhooks/:id', () => {
  it('returns 404 for unknown webhook', async () => {
    mockDb.select.mockImplementation(() => mockDb._makeChain(null));
    const res = await request(app).patch('/api/webhooks/nonexistent').send({ enabled: false });
    expect(res.status).toBe(404);
  });

  it('returns 400 when no valid fields provided', async () => {
    const res = await request(app).patch('/api/webhooks/wh-123').send({});
    expect(res.status).toBe(400);
  });

  it('returns 400 when url is not HTTPS', async () => {
    const res = await request(app)
      .patch('/api/webhooks/wh-123')
      .send({ url: 'http://bad.com/hook' });
    expect(res.status).toBe(400);
  });

  it('returns 400 when enabled is not boolean', async () => {
    const res = await request(app)
      .patch('/api/webhooks/wh-123')
      .send({ enabled: 'yes' });
    expect(res.status).toBe(400);
  });

  it('updates enabled flag', async () => {
    const updatedRow = { ...mockWebhookRow, enabled: false };
    // First select returns existing, second returns updated
    mockDb.select
      .mockImplementationOnce(() => mockDb._makeChain(mockWebhookRow))
      .mockImplementationOnce(() => mockDb._makeChain(updatedRow));

    const res = await request(app).patch('/api/webhooks/wh-123').send({ enabled: false });
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
    expect(mockDb.update).toHaveBeenCalled();
  });
});

describe('DELETE /api/webhooks/:id', () => {
  it('returns 404 for unknown webhook', async () => {
    mockDb.select.mockImplementation(() => mockDb._makeChain(null));
    const res = await request(app).delete('/api/webhooks/nonexistent');
    expect(res.status).toBe(404);
  });

  it('returns 204 on success', async () => {
    const res = await request(app).delete('/api/webhooks/wh-123');
    expect(res.status).toBe(204);
    expect(mockDb.delete).toHaveBeenCalled();
  });
});

describe('GET /api/webhooks/:id/deliveries', () => {
  it('returns 404 for unknown webhook', async () => {
    mockDb.select.mockImplementation(() => mockDb._makeChain(null));
    const res = await request(app).get('/api/webhooks/nonexistent/deliveries');
    expect(res.status).toBe(404);
  });

  it('returns delivery list', async () => {
    const stubDelivery = {
      id: 'del-1',
      webhookId: 'wh-123',
      eventType: 'scan.completed',
      status: 'delivered',
      attempts: 1,
    };
    // First select: webhook lookup; second select: deliveries list
    mockDb.select
      .mockImplementationOnce(() => mockDb._makeChain(mockWebhookRow))
      .mockImplementationOnce(() => mockDb._makeChain([stubDelivery]));

    const res = await request(app).get('/api/webhooks/wh-123/deliveries');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0].id).toBe('del-1');
  });
});

describe('POST /api/webhooks/:id/test', () => {
  it('returns 404 for unknown webhook', async () => {
    mockDb.select.mockImplementation(() => mockDb._makeChain(null));
    const res = await request(app).post('/api/webhooks/nonexistent/test');
    expect(res.status).toBe(404);
  });

  it('enqueues a test ping and returns deliveryId', async () => {
    const res = await request(app).post('/api/webhooks/wh-123/test');
    expect(res.status).toBe(200);
    expect(typeof res.body.deliveryId).toBe('string');
    expect(res.body.message).toMatch(/ping/i);
  });
});
