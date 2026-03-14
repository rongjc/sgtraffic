import { Router, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { db } from '../db';
import { scans, scanFindings } from '../db/schema';
import { eq } from 'drizzle-orm';

// APK files are ZIP files; magic bytes: PK\x03\x04
const APK_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

function hasApkMagicBytes(filePath: string): boolean {
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.alloc(4);
  try {
    fs.readSync(fd, buf, 0, 4, 0);
    return buf.equals(APK_MAGIC);
  } finally {
    fs.closeSync(fd);
  }
}

const router = Router();

// Rate limit: 10 uploads/IP/hour
const uploadRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`[RateLimit] /api/scans upload exceeded by IP ${req.ip}`);
    res.status(429).json({ error: 'Too many uploads. Limit is 10 per hour.', retryAfter: 3600 });
  },
});

// Uploads directory — outside the project tree, not reachable via HTTP
const UPLOADS_DIR = process.env.UPLOADS_DIR ?? path.join(os.homedir(), '.apk-scanner', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, _file, cb) => {
    // Use cryptographically secure UUID; drop original name to prevent path traversal
    cb(null, `${crypto.randomUUID()}.apk`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB
  fileFilter: (_req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== '.apk') {
      return cb(new Error('Only .apk files are allowed'));
    }
    cb(null, true);
  },
});

function generateId(): string {
  return crypto.randomUUID();
}

function sha256File(filePath: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

// POST /api/scans — upload APK
router.post('/', uploadRateLimiter, upload.single('file'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.file) {
      res.status(400).json({ error: 'No file uploaded' });
      return;
    }

    // Verify APK magic bytes (PK zip signature) — reject anything that isn't a real ZIP/APK
    if (!hasApkMagicBytes(req.file.path)) {
      fs.unlinkSync(req.file.path);
      res.status(400).json({ error: 'Invalid file: not a valid APK (bad magic bytes)' });
      return;
    }

    const sha256 = sha256File(req.file.path);
    const id = generateId();

    db.insert(scans).values({
      id,
      filename: req.file.originalname,
      fileHashSha256: sha256,
      status: 'pending',
      verdict: 'unknown',
      phaCategories: '[]',
    }).run();

    // Queue the job (job queue imported lazily to avoid circular deps)
    const { jobQueue } = await import('../jobs/queue');
    jobQueue.enqueue({ scanId: id, filePath: req.file.path });

    res.status(201).json({ id, status: 'pending' });
  } catch (err) {
    next(err);
  }
});

// GET /api/scans — list all scans
router.get('/', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const rows = db.select().from(scans).orderBy(scans.createdAt).all();
    res.json(rows.map(formatScan));
  } catch (err) {
    next(err);
  }
});

// GET /api/scans/:id — get single scan
router.get('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const row = db.select().from(scans).where(eq(scans.id, req.params.id)).get();
    if (!row) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    res.json(formatScan(row));
  } catch (err) {
    next(err);
  }
});

// GET /api/scans/:id/findings — get findings for a scan
router.get('/:id/findings', (req: Request, res: Response, next: NextFunction) => {
  try {
    const scan = db.select().from(scans).where(eq(scans.id, req.params.id)).get();
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    const findings = db.select().from(scanFindings).where(eq(scanFindings.scanId, req.params.id)).all();
    res.json(findings);
  } catch (err) {
    next(err);
  }
});

function formatScan(row: typeof scans.$inferSelect) {
  return {
    ...row,
    phaCategories: JSON.parse(row.phaCategories ?? '[]'),
  };
}

export default router;
