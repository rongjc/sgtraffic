# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

# Copy root workspace manifests
COPY package*.json ./
COPY packages/api/package*.json ./packages/api/

# Install all deps (workspace-aware)
RUN npm ci --workspace=packages/api

# Copy API source
COPY packages/api ./packages/api

# Build TypeScript
RUN npm run build -w packages/api

# Production stage
FROM node:20-alpine
WORKDIR /app

# Copy built output and production deps
COPY --from=builder /app/packages/api/dist ./dist
COPY --from=builder /app/packages/api/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules

# Uploads directory (mount a volume over this in production)
RUN mkdir -p /app/uploads

EXPOSE 3001
ENV NODE_ENV=production

CMD ["node", "dist/index.js"]
