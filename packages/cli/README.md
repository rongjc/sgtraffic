# apk-scanner-cli

CLI tool for the APK / Mobile App malware scanner REST API. Designed for use in CI/CD pipelines.

## Installation

```bash
pip install apk-scanner-cli
```

## Configuration

Set env vars (or pass as CLI flags):

| Env var           | Flag        | Description                                    | Default                   |
| ----------------- | ----------- | ---------------------------------------------- | ------------------------- |
| `SCANNER_API_URL` | `--api-url` | Base URL of the scanner API                    | `http://localhost:3001`   |
| `SCANNER_API_KEY` | `--api-key` | API key sent as `Authorization: Bearer <key>`  | _(none)_                  |

## Commands

### `scan <file>`

Upload an APK, IPA, or zip file and wait for the verdict.

```bash
apk-scanner scan app-release.apk --fail-above 60 --format table
```

**Options:**

| Flag              | Default | Description                                         |
| ----------------- | ------- | --------------------------------------------------- |
| `--fail-above N`  | `60`    | Exit non-zero when risk score exceeds N             |
| `--poll-interval` | `3`     | Seconds between status polls                        |
| `--timeout`       | `300`   | Max seconds to wait for completion                  |
| `--format`        | `text`  | Output format: `text`, `json`, `table`              |

**Exit codes:**

| Code | Meaning            |
| ---- | ------------------ |
| `0`  | Clean              |
| `1`  | Suspicious         |
| `2`  | PHA / malware      |
| `3`  | Error / timeout    |

### `status <scan-id>`

Check the current status of a scan.

```bash
apk-scanner status a1b2c3d4-...
```

### `history`

List recent scans.

```bash
apk-scanner history --limit 20 --format table
```

### `report <scan-id>`

Download the PDF report for a completed scan.

```bash
apk-scanner report a1b2c3d4-... --output report.pdf
```

## CI/CD Integration

See [`docs/github-actions.yml`](docs/github-actions.yml) and [`docs/gitlab-ci.yml`](docs/gitlab-ci.yml) for example pipeline configurations.

### Quick GitHub Actions example

```yaml
- name: Install scanner CLI
  run: pip install apk-scanner-cli

- name: Run security scan
  env:
    SCANNER_API_URL: ${{ secrets.SCANNER_API_URL }}
    SCANNER_API_KEY: ${{ secrets.SCANNER_API_KEY }}
  run: apk-scanner scan app-release.apk --fail-above 60
```

### Quick GitLab CI example

```yaml
mobile-security-scan:
  image: python:3.11-slim
  before_script:
    - pip install apk-scanner-cli
  script:
    - apk-scanner scan app-release.apk --fail-above 60 --format table
```
