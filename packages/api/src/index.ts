import express from 'express';
import path from 'path';
import { initDb } from './db';
import { errorHandler, notFound } from './middleware/errorHandler';
import scansRouter from './routes/scans';
import metricsRouter from './routes/metrics';
import { jobQueue } from './jobs/queue';
import { processApkJob } from './jobs/processor';

const app = express();
const PORT = process.env.PORT ?? 3001;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS for dev (web package on different port)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Routes
app.use('/api/scans', scansRouter);
app.use('/api/metrics', metricsRouter);

// 404 + error handling
app.use(notFound);
app.use(errorHandler);

// Boot
initDb();
jobQueue.register(processApkJob);
app.listen(PORT, () => {
  console.log(`[API] Listening on http://localhost:${PORT}`);
  console.log(`[API] Analyzer endpoint: ${process.env.ANALYZER_URL ?? 'http://127.0.0.1:5001'}`);
});

export default app;
