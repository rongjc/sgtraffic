# API Reference

Base URL: `http://localhost:3001` (default)

All endpoints return JSON. File upload uses `multipart/form-data`. Errors return `{ "error": "<message>" }`.

## Authentication

Pass your API key as a Bearer token:

```
Authorization: Bearer <api-key>
```

For local development without auth the header can be omitted.

---

## Health

### `GET /api/health`

Returns service status.

**Response `200`:**

```json
{
  "status": "ok",
  "timestamp": "2026-03-14T12:00:00.000Z"
}
```

---

## Scans

### `POST /api/scans`

Upload a file for analysis. Returns immediately with a scan ID; analysis runs asynchronously.

**Request:** `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | file | Yes | `.apk`, `.ipa`, `.zip`, `.appx`, or `.msix` (max 100 MB) |

**Response `201`:**

```json
{
  "id": "a1b2c3d4-...",
  "status": "pending"
}
```

**Errors:**

| Status | Condition |
|---|---|
| `400` | No file provided |
| `400` | Unsupported file extension |
| `413` | File exceeds 100 MB |

---

### `GET /api/scans`

List all scans, sorted by creation time ascending.

**Response `200`:** array of [Scan objects](#scan-object).

---

### `GET /api/scans/:id`

Get a single scan by ID.

**Response `200`:** [Scan object](#scan-object).

**Errors:**

| Status | Condition |
|---|---|
| `404` | Scan not found |

---

### `GET /api/scans/:id/findings`

Get all findings for a completed scan.

**Response `200`:** array of [Finding objects](#finding-object).

**Errors:**

| Status | Condition |
|---|---|
| `404` | Scan not found |

---

### `GET /api/scans/:id/report`

Generate and download a PDF report. Requires scan `status === "done"`.

**Response `200`:** `Content-Type: application/pdf` binary stream.

**Response headers:**

```
Content-Type: application/pdf
Content-Disposition: attachment; filename="scan-report-<id>.pdf"
```

**Errors:**

| Status | Condition |
|---|---|
| `404` | Scan not found |
| `409` | Scan not yet complete |

---

### `POST /api/scans/:id/dynamic-analysis`

Trigger Android dynamic analysis for a completed APK scan.

**Request body (JSON):**

| Field | Type | Default | Description |
|---|---|---|---|
| `timeout` | integer | `120` | Analysis duration in seconds (max `600`) |

**Response `202`:**

```json
{
  "scanId": "a1b2c3d4-...",
  "dynamicStatus": "pending",
  "message": "Dynamic analysis queued (timeout=120s)"
}
```

**Errors:**

| Status | Condition |
|---|---|
| `404` | Scan not found |
| `409` | Static analysis not yet complete |
| `409` | Dynamic analysis already running |
| `409` | Original APK file no longer on disk |
| `422` | Scan is not an APK (dynamic analysis only supports APK) |

---

### `POST /api/scans/:id/ios-dynamic-analysis`

Trigger iOS dynamic analysis for a completed IPA scan.

**Request body (JSON):**

| Field | Type | Default | Description |
|---|---|---|---|
| `timeout` | integer | `120` | Analysis duration in seconds (max `600`) |

**Response `202`:**

```json
{
  "scanId": "a1b2c3d4-...",
  "iosDynamicStatus": "pending",
  "message": "iOS dynamic analysis queued (timeout=120s)"
}
```

**Errors:**

| Status | Condition |
|---|---|
| `404` | Scan not found |
| `409` | Static analysis not yet complete |
| `409` | iOS dynamic analysis already running |
| `409` | Original IPA file no longer on disk |
| `422` | Scan is not an IPA |

---

## Metrics

### `GET /api/metrics`

Aggregate analytics data for the dashboard.

**Response `200`:**

```json
{
  "overview": {
    "totalScans": 1234,
    "scansToday": 12,
    "scansThisWeek": 89,
    "scansThisMonth": 432,
    "errorRate": 0.02,
    "avgScanTimeMs": 8500,
    "avgRiskScore": 34.2
  },
  "verdictBreakdown": {
    "clean": 900,
    "suspicious": 200,
    "pha": 100,
    "unknown": 34
  },
  "detectionRate": 0.243,
  "scanVolumeByDay": [
    { "date": "2026-02-14", "count": 15 }
  ],
  "topPhaCategories": [
    { "category": "data_exfiltration", "count": 45 }
  ],
  "findingsBySeverity": {
    "critical": 120,
    "high": 340,
    "medium": 800,
    "low": 1200
  },
  "topRules": [
    { "rule": "DANGEROUS_PERMISSION", "count": 520 }
  ],
  "userActivity": [
    { "user_id": "user-123", "scan_count": 45 }
  ],
  "riskScoreDistribution": {
    "low": 600,
    "moderate": 400,
    "high": 180,
    "critical": 54
  },
  "trackerPrevalence": [
    { "tracker": "Firebase", "count": 320 }
  ],
  "privacyScoreDistribution": {
    "low": 500,
    "moderate": 400,
    "high": 250,
    "critical": 84,
    "avgScore": 38.5
  }
}
```

---

## Data Models

### Scan Object

```json
{
  "id": "a1b2c3d4-e5f6-...",
  "filename": "app-release.apk",
  "fileHashSha256": "abc123...",
  "status": "done",
  "verdict": "pha",
  "phaCategories": ["data_exfiltration", "spyware"],
  "riskScore": 78,
  "errorMessage": null,
  "sourceType": "apk",
  "createdAt": "2026-03-14T12:00:00.000Z",
  "completedAt": "2026-03-14T12:00:12.000Z",
  "metadata": {
    "package_name": "com.example.app",
    "version": "1.2.3",
    "min_sdk": 24,
    "target_sdk": 34,
    "permissions": ["android.permission.INTERNET", "android.permission.READ_CONTACTS"],
    "sha256": "abc123..."
  },
  "privacyScore": 62,
  "trackersDetected": ["Firebase", "Adjust"],
  "dynamicStatus": "done",
  "dynamicRiskDelta": 12,
  "dynamicEventsCapured": 347,
  "dynamicTrafficFlows": 23,
  "dynamicPackageName": "com.example.app",
  "dynamicError": null,
  "dynamicCompletedAt": "2026-03-14T12:02:30.000Z",
  "iosDynamicStatus": null,
  "userId": null
}
```

**Status values:**

| Value | Description |
|---|---|
| `pending` | Queued, not yet started |
| `analyzing` | Analysis in progress |
| `done` | Complete — results available |
| `error` | Analysis failed — see `errorMessage` |

**Source type values:**

| Value | File type |
|---|---|
| `apk` | Android package |
| `ipa` | iOS package |
| `android_source` | Android source code zip |
| `ios_source` | iOS source code zip |
| `appx` | Windows Mobile package |
| `null` | Unknown (source type resolved after analysis for zip files) |

---

### Finding Object

```json
{
  "id": "f1e2d3c4-...",
  "scanId": "a1b2c3d4-...",
  "category": "crypto",
  "severity": "high",
  "rule": "WEAK_CRYPTO_ALGORITHM",
  "description": "Use of MD5 for security-sensitive hashing detected.",
  "evidence": "MessageDigest.getInstance(\"MD5\")"
}
```

**Severity values:** `critical`, `high`, `medium`, `low`

**Common rule IDs:**

| Rule | Category | Severity | Description |
|---|---|---|---|
| `DANGEROUS_PERMISSION` | permissions | high | Dangerous permission requested |
| `HARDCODED_SECRET` | crypto | critical | API key or secret in plaintext |
| `WEAK_CRYPTO_ALGORITHM` | crypto | high | MD5 or SHA-1 used for security |
| `CLEARTEXT_TRAFFIC` | network | high | HTTP (non-TLS) traffic allowed |
| `DEBUG_ENABLED` | manifest | medium | `android:debuggable="true"` |
| `EXPORTED_COMPONENT` | manifest | medium | Activity/Service exported without permission |
| `ALLOW_BACKUP` | manifest | low | `android:allowBackup="true"` |
| `ATS_DISABLED` | network | high | iOS App Transport Security disabled |
| `INSECURE_RANDOM` | crypto | medium | `Math.random()` or weak RNG used |
| `TRACKER_SDK` | privacy | medium | Known tracker SDK detected |
| `DATA_EXFILTRATION` | pha | critical | Contacts/SMS exfiltration pattern |

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Human-readable error message"
}
```

| Status | Meaning |
|---|---|
| `400` | Bad request — missing or invalid input |
| `404` | Resource not found |
| `409` | Conflict — operation not allowed in current state |
| `413` | Payload too large |
| `422` | Unprocessable — invalid operation for this resource type |
| `500` | Internal server error |
