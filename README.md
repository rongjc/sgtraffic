# APK / Mobile App Security Scanner

A production-ready mobile application security analysis platform with feature parity to MobSF. Supports static and dynamic analysis for Android (APK), iOS (IPA), source code (zip), and Windows Mobile (APPX) apps.

## Quick Start

```bash
# Start all services with Docker Compose
docker compose up

# Web UI
open http://localhost

# REST API
curl http://localhost:3001/api/health
```

## Documentation

| Guide | Description |
|---|---|
| [User Guide](docs/user-guide.md) | How to scan APK, IPA, source, and run dynamic analysis |
| [API Reference](docs/api-reference.md) | Full REST API documentation |
| [Deployment Guide](docs/deployment.md) | Docker, Cloud Run, and self-hosted setup |
| [CI/CD Integration](docs/cicd.md) | GitHub Actions, GitLab CI, and other pipeline examples |

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌─────────────────┐
│  Web UI      │    │  Node.js API │    │  Python Analyzer│
│  (React/Vite)│───▶│  (Express)   │───▶│  (Flask)        │
│  :80         │    │  :3001       │    │  :5001          │
└──────────────┘    └──────┬───────┘    └─────────────────┘
                           │                      │
                    ┌──────▼───────┐    ┌─────────▼───────┐
                    │  MongoDB     │    │  Android Emulator│
                    │  (scans DB)  │    │  + mitmproxy     │
                    └──────────────┘    └─────────────────┘
```

## Capabilities

| Analysis Type | Supported |
|---|---|
| APK static analysis | Yes — 14 PHA categories, 29+ rules |
| IPA (iOS) static analysis | Yes |
| Android source code analysis | Yes |
| iOS source code analysis | Yes |
| APPX (Windows Mobile) analysis | Yes |
| Android dynamic analysis (Frida) | Yes |
| iOS dynamic analysis (Frida) | Yes |
| API fuzzing | Yes |
| Privacy / tracker detection | Yes |
| PDF report export | Yes |
| CI/CD CLI | Yes — `pip install apk-scanner-cli` |

## Packages

- `packages/analyzer` — Python analysis engine (Flask)
- `packages/api` — Node.js REST API (Express + MongoDB)
- `packages/web` — React dashboard (Vite + TailwindCSS)
- `packages/cli` — Python CLI for CI/CD pipelines
