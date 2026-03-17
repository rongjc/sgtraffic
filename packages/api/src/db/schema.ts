import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  apiKey: text('api_key').notNull().unique(),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});

export const scans = sqliteTable('scans', {
  id: text('id').primaryKey(),
  userId: text('user_id').references(() => users.id),
  filename: text('filename').notNull(),
  fileHashSha256: text('file_hash_sha256').notNull(),
  status: text('status', { enum: ['pending', 'analyzing', 'done', 'error'] })
    .notNull()
    .default('pending'),
  verdict: text('verdict', { enum: ['clean', 'pha', 'suspicious', 'unknown'] })
    .notNull()
    .default('unknown'),
  phaCategories: text('pha_categories').notNull().default('[]'), // JSON array stored as text
  riskScore: integer('risk_score'),
  errorMessage: text('error_message'),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
  completedAt: text('completed_at'),
});

export const scanFindings = sqliteTable('scan_findings', {
  id: text('id').primaryKey(),
  scanId: text('scan_id')
    .notNull()
    .references(() => scans.id, { onDelete: 'cascade' }),
  category: text('category').notNull(),
  severity: text('severity', { enum: ['critical', 'high', 'medium', 'low'] }).notNull(),
  rule: text('rule').notNull(),
  description: text('description').notNull(),
  evidence: text('evidence'),
});

export const webhooks = sqliteTable('webhooks', {
  id: text('id').primaryKey(),
  userId: text('user_id').references(() => users.id),
  url: text('url').notNull(),
  eventTypes: text('event_types').notNull().default('["scan.completed","scan.failed"]'), // JSON array
  signingSecret: text('signing_secret').notNull(),
  enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});

export const webhookDeliveries = sqliteTable('webhook_deliveries', {
  id: text('id').primaryKey(),
  webhookId: text('webhook_id')
    .notNull()
    .references(() => webhooks.id, { onDelete: 'cascade' }),
  scanId: text('scan_id'),
  eventType: text('event_type').notNull(),
  payload: text('payload').notNull(), // JSON
  status: text('status', { enum: ['pending', 'delivered', 'failed'] }).notNull().default('pending'),
  responseCode: integer('response_code'),
  responseBody: text('response_body'),
  attempts: integer('attempts').notNull().default(0),
  nextRetryAt: text('next_retry_at'),
  deliveredAt: text('delivered_at'),
  createdAt: text('created_at').notNull().default(sql`(datetime('now'))`),
});
