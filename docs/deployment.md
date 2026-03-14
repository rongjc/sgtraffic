# Deployment Guide

## Contents

- [Prerequisites](#prerequisites)
- [Docker Compose (recommended)](#docker-compose-recommended)
- [Google Cloud Run](#google-cloud-run)
- [Self-Hosted (manual)](#self-hosted-manual)
- [Environment Variables](#environment-variables)
- [Dynamic Analysis Infrastructure](#dynamic-analysis-infrastructure)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker + Docker Compose v2 | For Docker-based deployments |
| MongoDB 6+ | Required by the API service |
| Node.js 20+ | For running the API outside Docker |
| Python 3.11+ | For running the analyzer outside Docker |
| Google Cloud SDK | For Cloud Run deployment only |

---

## Docker Compose (recommended)

The fastest way to get a full stack running locally or on a VM.

### 1. Clone and configure

```bash
git clone <repo-url> apk-scanner
cd apk-scanner

# Create environment file
cp .env.example .env
# Edit .env and set MONGODB_URI
```

**.env:**

```env
MONGODB_URI=mongodb://mongo:27017/apk-scanner
DYNAMIC_TIMEOUT=120
```

### 2. Start all services

```bash
docker compose up -d
```

Services started:

| Service | Port | Description |
|---|---|---|
| `web` | `80` | React dashboard (nginx) |
| `api` | `3001` | Node.js REST API |
| `analyzer` | `5001` | Python analysis engine |
| `emulator` | `5555` (ADB), `27042` (Frida), `6080` (VNC) | Android emulator |
| `mitmproxy` | `8080` (proxy), `8081` (web UI) | Traffic interceptor |

### 3. Check health

```bash
curl http://localhost:3001/api/health
open http://localhost
```

### 4. Stop

```bash
docker compose down
# Preserve uploads volume:
docker compose down --volumes=false
```

### Emulator startup time

The Android emulator takes **2–3 minutes** to boot on first start. The analyzer will wait for it before accepting dynamic analysis jobs. You can monitor boot status via the noVNC interface at `http://localhost:6080`.

---

## Google Cloud Run

For production deployments. Uses a multi-container Cloud Run service (API + Analyzer as a sidecar) plus a separate Web frontend service.

### 1. Prerequisites

```bash
# Install and authenticate Google Cloud SDK
gcloud auth login
gcloud auth configure-docker <REGION>-docker.pkg.dev
```

### 2. Set up MongoDB

Cloud Run services need an external MongoDB. Options:

- **MongoDB Atlas** (recommended) — create a free cluster at [cloud.mongodb.com](https://cloud.mongodb.com) and get the connection string.
- **Google Cloud Bigtable / Firestore** — not directly compatible; use Atlas or a self-hosted Mongo VM.

### 3. Deploy

```bash
export MONGODB_URI="mongodb+srv://user:pass@cluster.mongodb.net/apk-scanner"

./deploy.sh <PROJECT_ID> <REGION>
# Example: ./deploy.sh my-gcp-project us-central1
```

The script:
1. Creates an Artifact Registry repository `apk-scanner`
2. Builds and pushes Docker images for `api`, `analyzer`, and `web`
3. Stores `MONGODB_URI` in Google Secret Manager as `apk-scanner-secrets`
4. Deploys the multi-container API+Analyzer service using `cloud-run.yaml`
5. Deploys the Web frontend as a separate service
6. Prints the public URLs on completion

### 4. Output

```
==> Deployment complete!
    API:     https://apk-scanner-xxxx-uc.a.run.app
    Web UI:  https://apk-scanner-web-xxxx-uc.a.run.app
```

### Cloud Run limitations

| Limitation | Impact |
|---|---|
| No persistent disk | Uploaded files live in an ephemeral in-memory volume (512 MB). Files are lost on restart; scans must complete within the request lifecycle. |
| No GPU / QEMU acceleration | Android emulator (dynamic analysis) is not available on Cloud Run. Dynamic analysis requires a VM-based deployment. |
| Max request timeout: 3600s | Long scans may need the timeout increased. |

**Dynamic analysis on Cloud Run:** not supported. For dynamic analysis, deploy to a Compute Engine VM using Docker Compose.

### Updating images

```bash
# Rebuild and push a single service
docker build -t <REGION>-docker.pkg.dev/<PROJECT>/apk-scanner/api:latest \
  -f packages/api/Dockerfile .
docker push <REGION>-docker.pkg.dev/<PROJECT>/apk-scanner/api:latest

# Re-deploy
gcloud run services update apk-scanner --region=<REGION>
```

---

## Self-Hosted (manual)

For environments where Docker is not available.

### API (Node.js)

```bash
cd packages/api

# Install dependencies
npm install

# Set environment variables
export MONGODB_URI="mongodb://localhost:27017/apk-scanner"
export ANALYZER_URL="http://localhost:5001"
export UPLOADS_DIR="/var/apk-scanner/uploads"
export PORT=3001

# Build
npm run build

# Start
node dist/index.js
```

### Analyzer (Python)

```bash
cd packages/analyzer

# Install dependencies (use a virtualenv)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Set environment variables
export EMULATOR_HOST=localhost
export EMULATOR_ADB_PORT=5555
export EMULATOR_FRIDA_PORT=27042
export MITMPROXY_HOST=localhost
export MITMPROXY_API_PORT=8081
export ANALYZER_PORT=5001

# Start
python -m src.server
```

### Web (React)

```bash
cd packages/web

# Install and build
npm install
npm run build

# Serve with nginx or any static file server
# Point it at the dist/ directory and proxy /api/* to the API service
```

Nginx config snippet:

```nginx
server {
    listen 80;

    location /api/ {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        client_max_body_size 100m;
    }

    location / {
        root /var/www/apk-scanner/dist;
        try_files $uri $uri/ /index.html;
    }
}
```

### MongoDB

For production, use a replica set or MongoDB Atlas. For development:

```bash
# macOS
brew install mongodb-community
brew services start mongodb-community

# Ubuntu
sudo apt install -y mongodb
sudo systemctl start mongodb
```

---

## Environment Variables

### API (`packages/api`)

| Variable | Default | Description |
|---|---|---|
| `MONGODB_URI` | — | MongoDB connection string **(required)** |
| `ANALYZER_URL` | `http://127.0.0.1:5001` | URL of the Python analyzer service |
| `UPLOADS_DIR` | `./uploads` | Directory for uploaded files |
| `PORT` | `3001` | HTTP port |
| `NODE_ENV` | `development` | `production` disables verbose logging |

### Analyzer (`packages/analyzer`)

| Variable | Default | Description |
|---|---|---|
| `ANALYZER_PORT` | `5001` | HTTP port |
| `EMULATOR_HOST` | `emulator` | Android emulator hostname |
| `EMULATOR_ADB_PORT` | `5555` | ADB port |
| `EMULATOR_FRIDA_PORT` | `27042` | Frida server port |
| `MITMPROXY_HOST` | `mitmproxy` | mitmproxy hostname |
| `MITMPROXY_API_PORT` | `8081` | mitmproxy REST API port |
| `DYNAMIC_TIMEOUT` | `120` | Default dynamic analysis timeout (seconds) |

---

## Dynamic Analysis Infrastructure

Dynamic analysis requires two additional services:

### Android Emulator

Uses the `budtmo/docker-android:emulator_14.0` image with QEMU + Android 14 + Frida server pre-installed.

```bash
# Hardware virtualisation is required
# On Linux, ensure /dev/kvm is accessible:
ls -la /dev/kvm
sudo usermod -aG kvm $USER
```

The emulator profile used is **Samsung Galaxy S10**. To change it, edit `EMULATOR_DEVICE` in `docker-compose.yml`.

**noVNC debug UI:** browse to `http://localhost:6080` to see the emulator screen while dynamic analysis runs.

### mitmproxy

Acts as an HTTP/HTTPS MITM proxy for the emulator. The analyzer configures the emulator to route all traffic through mitmproxy at analysis start.

- Proxy listener: `:8080`
- Web UI / API: `:8081` (`http://localhost:8081`)

Traffic flows captured during dynamic analysis are returned as part of the scan result (`dynamicTrafficFlows`).
