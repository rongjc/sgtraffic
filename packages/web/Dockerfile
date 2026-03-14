# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
COPY packages/web/package*.json ./packages/web/

RUN npm ci --workspace=packages/web

COPY packages/web ./packages/web

# VITE_API_URL can be injected at build time if the API is at a non-default path
ARG VITE_API_URL=/api
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build -w packages/web

# Production stage — nginx to serve static assets
FROM nginx:stable-alpine
COPY --from=builder /app/packages/web/dist /usr/share/nginx/html

# nginx config: serve static files, proxy /api to the API service
COPY packages/web/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
