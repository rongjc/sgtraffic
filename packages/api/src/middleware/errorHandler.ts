import { Request, Response, NextFunction } from 'express';

export interface AppError extends Error {
  statusCode?: number;
}

export function errorHandler(
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const status = err.statusCode ?? 500;
  const message = err.message ?? 'Internal server error';

  console.error(`[Error] ${status} ${req.method} ${req.path}: ${message}`);
  if (status === 500) {
    console.error(err.stack);
  }

  res.status(status).json({ error: message });
}

export function notFound(req: Request, res: Response): void {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
}
