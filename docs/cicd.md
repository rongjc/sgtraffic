# CI/CD Integration Guide

Integrate mobile security scanning into your build pipeline using the `apk-scanner-cli` Python package.

## Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Bitbucket Pipelines](#bitbucket-pipelines)
- [CircleCI](#circleci)
- [CLI Reference](#cli-reference)
- [Exit Codes](#exit-codes)
- [Tips](#tips)

---

## Installation

```bash
pip install apk-scanner-cli
```

The CLI requires Python 3.9+. It is tested on Linux, macOS, and Windows.

---

## Configuration

Set environment variables or pass flags on every command:

| Env var | Flag | Default | Description |
|---|---|---|---|
| `SCANNER_API_URL` | `--api-url` | `http://localhost:3001` | Base URL of the scanner API |
| `SCANNER_API_KEY` | `--api-key` | _(none)_ | Bearer token for the API |

For CI/CD, store these as secrets (not plaintext):

- **GitHub Actions:** Settings → Secrets and variables → Actions
- **GitLab CI:** Settings → CI/CD → Variables (mark `SCANNER_API_KEY` as Masked)
- **Bitbucket Pipelines:** Repository Settings → Repository Variables (mark as Secured)
- **CircleCI:** Project Settings → Environment Variables

---

## GitHub Actions

### Basic scan

```yaml
# .github/workflows/mobile-security-scan.yml
name: Mobile Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Build APK
        run: ./gradlew assembleRelease

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install scanner CLI
        run: pip install apk-scanner-cli

      - name: Scan APK
        env:
          SCANNER_API_URL: ${{ secrets.SCANNER_API_URL }}
          SCANNER_API_KEY: ${{ secrets.SCANNER_API_KEY }}
        run: |
          apk-scanner scan app/build/outputs/apk/release/app-release.apk \
            --fail-above 60 \
            --format table \
            --timeout 300
```

### With PDF report artifact

```yaml
      - name: Scan and capture ID
        id: scan
        env:
          SCANNER_API_URL: ${{ secrets.SCANNER_API_URL }}
          SCANNER_API_KEY: ${{ secrets.SCANNER_API_KEY }}
        run: |
          # Capture scan ID from JSON output
          SCAN_ID=$(apk-scanner scan app/build/outputs/apk/release/app-release.apk \
            --fail-above 60 --format json | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

      - name: Download PDF report
        if: always()
        env:
          SCANNER_API_URL: ${{ secrets.SCANNER_API_URL }}
          SCANNER_API_KEY: ${{ secrets.SCANNER_API_KEY }}
        run: apk-scanner report ${{ steps.scan.outputs.scan_id }} --output security-report.pdf

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-report
          path: security-report.pdf
          retention-days: 30
```

### iOS scan

```yaml
      - name: Build IPA
        run: |
          xcodebuild archive \
            -scheme MyApp \
            -archivePath MyApp.xcarchive
          xcodebuild -exportArchive \
            -archivePath MyApp.xcarchive \
            -exportOptionsPlist ExportOptions.plist \
            -exportPath ./

      - name: Scan IPA
        env:
          SCANNER_API_URL: ${{ secrets.SCANNER_API_URL }}
          SCANNER_API_KEY: ${{ secrets.SCANNER_API_KEY }}
        run: |
          apk-scanner scan MyApp.ipa --fail-above 60 --format table
```

---

## GitLab CI

Full example with build → scan → report stages:

```yaml
# .gitlab-ci.yml
stages:
  - build
  - security
  - report

build-apk:
  stage: build
  image: gradle:8-jdk17
  script:
    - ./gradlew assembleRelease
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release.apk
    expire_in: 1 hour

mobile-security-scan:
  stage: security
  image: python:3.11-slim
  needs: [build-apk]
  variables:
    FAIL_ABOVE: "60"
    SCAN_TIMEOUT: "300"
  before_script:
    - pip install --quiet apk-scanner-cli
  script:
    - |
      apk-scanner scan app/build/outputs/apk/release/app-release.apk \
        --fail-above "$FAIL_ABOVE" \
        --format table \
        --timeout "$SCAN_TIMEOUT"

download-security-report:
  stage: report
  image: python:3.11-slim
  needs: [mobile-security-scan]
  when: always
  before_script:
    - pip install --quiet apk-scanner-cli
  script:
    - |
      SCAN_ID=$(apk-scanner history --limit 1 --format json \
        | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
      apk-scanner report "$SCAN_ID" --output security-report.pdf
  artifacts:
    name: "security-scan-${CI_COMMIT_SHORT_SHA}"
    paths:
      - security-report.pdf
    expire_in: 30 days
    when: always

# Nightly scheduled scan of recent builds
nightly-scan:
  stage: security
  image: python:3.11-slim
  only:
    - schedules
  before_script:
    - pip install --quiet apk-scanner-cli
  script:
    - apk-scanner history --limit 20 --format table
```

---

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: python:3.11-slim

pipelines:
  default:
    - step:
        name: Build
        image: gradle:8-jdk17
        script:
          - ./gradlew assembleRelease
        artifacts:
          - app/build/outputs/apk/release/*.apk

    - step:
        name: Security Scan
        script:
          - pip install apk-scanner-cli
          - |
            apk-scanner scan app/build/outputs/apk/release/app-release.apk \
              --fail-above 60 \
              --format table \
              --timeout 300
        after-script:
          - pip install apk-scanner-cli
          - |
            SCAN_ID=$(apk-scanner history --limit 1 --format json \
              | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
            apk-scanner report "$SCAN_ID" --output security-report.pdf
        artifacts:
          - security-report.pdf
```

---

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  build-and-scan:
    docker:
      - image: cimg/android:2024.01
    steps:
      - checkout

      - run:
          name: Build APK
          command: ./gradlew assembleRelease

      - run:
          name: Install scanner CLI
          command: pip install apk-scanner-cli

      - run:
          name: Security scan
          command: |
            apk-scanner scan app/build/outputs/apk/release/app-release.apk \
              --fail-above 60 \
              --format table \
              --timeout 300
          environment:
            SCANNER_API_URL: $SCANNER_API_URL
            SCANNER_API_KEY: $SCANNER_API_KEY

      - run:
          name: Download PDF report
          when: always
          command: |
            SCAN_ID=$(apk-scanner history --limit 1 --format json \
              | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
            apk-scanner report "$SCAN_ID" --output security-report.pdf

      - store_artifacts:
          path: security-report.pdf

workflows:
  build-scan:
    jobs:
      - build-and-scan
```

---

## CLI Reference

### `apk-scanner scan <file>`

Upload and scan a file. Blocks until complete (or timeout).

```bash
apk-scanner scan app-release.apk \
  --fail-above 60 \
  --format table \
  --timeout 300
```

| Flag | Default | Description |
|---|---|---|
| `--fail-above N` | `60` | Exit non-zero when risk score exceeds N |
| `--poll-interval N` | `3` | Seconds between status polls |
| `--timeout N` | `300` | Max seconds to wait before giving up |
| `--format` | `text` | Output format: `text`, `json`, `table` |

### `apk-scanner status <scan-id>`

Check the current status of a scan.

```bash
apk-scanner status a1b2c3d4-e5f6-...
```

### `apk-scanner history`

List recent scans.

```bash
apk-scanner history --limit 20 --format table
```

| Flag | Default | Description |
|---|---|---|
| `--limit N` | `10` | Number of scans to return |
| `--format` | `text` | Output format: `text`, `json`, `table` |

### `apk-scanner report <scan-id>`

Download the PDF report for a completed scan.

```bash
apk-scanner report a1b2c3d4-... --output report.pdf
```

| Flag | Default | Description |
|---|---|---|
| `--output PATH` | `report.pdf` | Output file path |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — risk score at or below threshold |
| `1` | Suspicious — risk score exceeded threshold |
| `2` | PHA / malware confirmed |
| `3` | Error — scan failed, timed out, or CLI error |

Use the exit code to gate your pipeline:

```bash
apk-scanner scan app.apk --fail-above 60
if [ $? -eq 2 ]; then
  echo "MALWARE DETECTED — blocking release"
  exit 1
fi
```

---

## Tips

**Set a threshold appropriate for your risk tolerance.** The default `--fail-above 60` blocks on high-risk apps. For stricter gates use `--fail-above 40`; for warning-only use `--fail-above 90`.

**Run in parallel with unit tests** to avoid adding latency to your total pipeline time.

**Cache pip dependencies** to speed up installation:

```yaml
# GitHub Actions example
- uses: actions/cache@v4
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-apk-scanner-cli
```

**Source code scanning** requires zipping your project before uploading. Add a build step:

```bash
zip -r source.zip . \
  --exclude "*/build/*" \
  --exclude "*/node_modules/*" \
  --exclude "*/.git/*"
apk-scanner scan source.zip --fail-above 50
```

**Scan both debug and release builds** to catch issues introduced by ProGuard/R8 rules or release signing configs.
