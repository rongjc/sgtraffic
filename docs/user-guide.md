# User Guide

## Contents

- [Overview](#overview)
- [Web UI](#web-ui)
- [APK Analysis (Android)](#apk-analysis-android)
- [IPA Analysis (iOS)](#ipa-analysis-ios)
- [Source Code Analysis](#source-code-analysis)
- [Dynamic Analysis — Android](#dynamic-analysis--android)
- [Dynamic Analysis — iOS](#dynamic-analysis--ios)
- [Privacy Analysis](#privacy-analysis)
- [PDF Reports](#pdf-reports)
- [Understanding Results](#understanding-results)

---

## Overview

The scanner accepts mobile app files and returns a security verdict with detailed findings. Analysis runs asynchronously — you upload a file, get back a scan ID, then poll for results.

**Supported file types:**

| Extension | Analysis type |
|---|---|
| `.apk` | Android static analysis |
| `.ipa` | iOS static analysis |
| `.zip` | Android or iOS source code analysis |
| `.appx` / `.msix` | Windows Mobile static analysis |

**Verdicts:**

| Verdict | Meaning |
|---|---|
| `clean` | No significant threats found |
| `suspicious` | Potentially harmful behaviour detected |
| `pha` | Potentially Harmful Application — confirmed malware patterns |
| `unknown` | Analysis pending or inconclusive |

---

## Web UI

Open `http://localhost` (or your deployed URL) in a browser.

1. **Upload** — drag and drop or click to select a file (max 100 MB).
2. **Monitor** — the scan status updates in real time.
3. **Review** — click a completed scan to view the verdict, risk score, PHA categories, and individual findings.
4. **Report** — click **Download PDF** to export the full report.
5. **Dashboard** — the Analytics tab shows scan history, detection rates, severity breakdowns, and tracker prevalence.

---

## APK Analysis (Android)

### What it checks

- **Manifest analysis** — dangerous permissions, exported components, `allowBackup`, debuggable flag
- **DEX analysis** — bytecode patterns for crypto misuse, reflection abuse, native library loading
- **Certificate analysis** — debug certificates, weak signing algorithms, certificate validity
- **String analysis** — hardcoded secrets, suspicious URLs, obfuscated strings
- **Permission analysis** — over-privileged permission sets, permission combinations associated with spyware
- **PHA category detection** — 14 categories including ransomware, spyware, adware, trojans, backdoors

### Upload via CLI

```bash
apk-scanner scan app-release.apk --fail-above 60 --format table
```

### Upload via curl

```bash
curl -X POST http://localhost:3001/api/scans \
  -F "file=@app-release.apk"
# Returns: {"id": "<scan-id>", "status": "pending"}

# Poll for completion
curl http://localhost:3001/api/scans/<scan-id>
```

---

## IPA Analysis (iOS)

### What it checks

- **Info.plist analysis** — ATS (App Transport Security) misconfigurations, privacy usage descriptions, URL schemes
- **Entitlements analysis** — over-privileged entitlements (keychain sharing, push, HealthKit)
- **Binary analysis** — weak crypto patterns, insecure random number generation, unsafe API usage
- **Swift / ObjC patterns** — hardcoded secrets, logging of sensitive data, insecure storage
- **Embedded frameworks** — third-party SDK fingerprinting

### Upload

```bash
apk-scanner scan MyApp.ipa --fail-above 60
```

```bash
curl -X POST http://localhost:3001/api/scans \
  -F "file=@MyApp.ipa"
```

---

## Source Code Analysis

Upload a `.zip` archive containing an Android or iOS project. The analyzer detects the project type from the directory structure.

**Android source projects** — scans `AndroidManifest.xml`, Java/Kotlin source files, `build.gradle`.

**iOS source projects** — scans `Info.plist`, Swift/ObjC source files, `Podfile`.

### Package your project

```bash
# Android
zip -r my-android-app.zip . --exclude "*/build/*" "*/node_modules/*" "*/.git/*"

# iOS
zip -r my-ios-app.zip . --exclude "*/DerivedData/*" "*/Pods/*" "*/.git/*"
```

### Upload

```bash
apk-scanner scan my-android-app.zip --fail-above 60
```

```bash
curl -X POST http://localhost:3001/api/scans \
  -F "file=@my-android-app.zip"
```

---

## Dynamic Analysis — Android

Dynamic analysis runs the APK inside an Android emulator (Android 14, Samsung Galaxy S10 profile) with Frida instrumentation and mitmproxy traffic interception.

**Prerequisites:** static analysis must complete first (`status: "done"`).

### What it captures

- Network traffic (HTTP/HTTPS via mitmproxy)
- File system read/write operations
- Cryptographic operations (keys, algorithms, data)
- Inter-process communication
- Sensitive data leakage (contacts, location, SMS)
- Dynamic code loading

### Trigger via API

```bash
curl -X POST http://localhost:3001/api/scans/<scan-id>/dynamic-analysis \
  -H "Content-Type: application/json" \
  -d '{"timeout": 120}'
```

**Parameters:**

| Field | Type | Default | Description |
|---|---|---|---|
| `timeout` | integer | `120` | Max seconds to run (max `600`) |

**Response:**

```json
{
  "scanId": "<scan-id>",
  "dynamicStatus": "pending",
  "message": "Dynamic analysis queued (timeout=120s)"
}
```

Poll the scan: `GET /api/scans/<scan-id>` — check the `dynamicStatus` field.

**Dynamic result fields on the scan object:**

| Field | Description |
|---|---|
| `dynamicStatus` | `pending` / `running` / `done` / `error` |
| `dynamicRiskDelta` | Risk score increase from dynamic findings |
| `dynamicEventsCapured` | Number of runtime events logged |
| `dynamicTrafficFlows` | Number of unique network flows recorded |
| `dynamicPackageName` | Package name detected at runtime |

---

## Dynamic Analysis — iOS

iOS dynamic analysis runs the IPA in an iOS Simulator with Frida instrumentation.

**Prerequisites:** static IPA analysis must complete first.

### Trigger via API

```bash
curl -X POST http://localhost:3001/api/scans/<scan-id>/ios-dynamic-analysis \
  -H "Content-Type: application/json" \
  -d '{"timeout": 120}'
```

**Dynamic result fields:**

| Field | Description |
|---|---|
| `iosDynamicStatus` | `pending` / `running` / `done` / `error` |
| `iosDynamicRiskDelta` | Risk score increase from dynamic findings |
| `iosDynamicEventsCapured` | Number of runtime events logged |
| `iosDynamicTrafficFlows` | Number of unique network flows recorded |
| `iosDynamicBundleId` | Bundle ID detected at runtime |
| `iosDynamicSimulatorUdid` | Simulator UDID used |

---

## Privacy Analysis

Privacy analysis runs automatically as part of every static analysis. Results are included in the scan object and findings list.

**What it detects:**

- Known tracker SDKs (Adjust, AppsFlyer, Firebase, etc.)
- Data collection patterns (PII harvesting, device fingerprinting)
- Unnecessary data access (contacts, location, microphone, camera)
- GDPR / privacy compliance issues

**Scan fields:**

| Field | Description |
|---|---|
| `privacyScore` | 0–100 privacy risk score (higher = more risky) |
| `trackersDetected` | Array of detected tracker SDK names |

---

## PDF Reports

Download a full PDF report for any completed scan.

**Via Web UI:** click **Download PDF** on the scan detail page.

**Via CLI:**

```bash
apk-scanner report <scan-id> --output report.pdf
```

**Via API:**

```bash
curl -o report.pdf http://localhost:3001/api/scans/<scan-id>/report
```

Reports include:
- Executive summary with verdict and risk score
- Severity breakdown chart
- Full findings list with descriptions and evidence
- PHA category breakdown
- Privacy analysis summary
- Recommendations

---

## Understanding Results

### Risk Score

A 0–100 score computed from the severity and count of findings:

| Range | Level | Recommended action |
|---|---|---|
| 0–25 | Low | Monitor only |
| 26–50 | Moderate | Review findings before release |
| 51–75 | High | Block release; remediate critical findings |
| 76–100 | Critical | Do not distribute; treat as malware |

### Findings

Each finding has:

| Field | Values | Description |
|---|---|---|
| `category` | e.g. `crypto`, `network`, `permissions` | Finding category |
| `severity` | `critical`, `high`, `medium`, `low` | Impact severity |
| `rule` | e.g. `HARDCODED_SECRET` | Machine-readable rule ID |
| `description` | Human-readable explanation | What was found |
| `evidence` | Optional snippet or value | What triggered the rule |

### PHA Categories

14 categories aligned with Google Play Protect:

| Category | Description |
|---|---|
| `backdoor` | Remote access capabilities |
| `billing_fraud` | Unauthorized charges |
| `call_fraud` | Premium-rate call abuse |
| `click_fraud` | Ad click fraud |
| `commercial_spyware` | User surveillance without consent |
| `data_exfiltration` | Sending data to remote servers |
| `denial_of_service` | Battery/resource drain attacks |
| `hostile_downloader` | Downloads additional malicious payloads |
| `non_android_threat` | Targets Windows/iOS victims via Android vector |
| `phishing` | Credential harvesting UI |
| `ransomware` | File or screen ransomware |
| `rooting` | Privilege escalation |
| `sms_fraud` | Premium SMS abuse |
| `trojan` | Disguised malicious functionality |
