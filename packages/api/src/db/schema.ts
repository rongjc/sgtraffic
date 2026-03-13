import { sqliteTable, text, integer, real } from 'drizzle-orm/sqlite-core';
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
