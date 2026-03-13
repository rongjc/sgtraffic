import { Router, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { db } from '../db';
import { scans, scanFindings } from '../db/schema';
import { eq } from 'drizzle-orm';

const router = Router();

// Uploads directory
const UPLOADS_DIR = path.join(process.cwd(), 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const unique = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    cb(null, `${unique}${path.extname(file.originalname)}`);
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
router.post('/', upload.single('file'), async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.file) {
      res.status(400).json({ error: 'No file uploaded' });
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
