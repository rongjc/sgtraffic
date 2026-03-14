"""
Android Dynamic Analysis via Frida instrumentation.

Orchestrates:
  1. Android emulator (AVD) in a Docker container
  2. APK installation and launch
  3. Frida-based runtime hooks:
     - Network calls (HTTP/HTTPS, DNS, raw sockets)
     - File system operations (external storage, shared prefs)
     - Crypto operations (encryption/decryption, key generation)
     - SMS/telephony API calls
     - Content provider queries (contacts, SMS, call log)
     - Dynamic code loading (DexClassLoader, reflection)
  4. mitmproxy for TLS traffic interception
  5. Aggregates dynamic findings and integrates with risk scoring

Environment variables:
  EMULATOR_HOST       - hostname of the Android emulator service (default: emulator)
  EMULATOR_ADB_PORT   - ADB port on the emulator host (default: 5555)
  EMULATOR_FRIDA_PORT - Frida server port (default: 27042)
  MITMPROXY_HOST      - hostname for mitmproxy (default: mitmproxy)
  MITMPROXY_API_PORT  - mitmproxy HTTP API port (default: 8081)
  DYNAMIC_TIMEOUT     - seconds before analysis is terminated (default: 120)
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
EMULATOR_HOST = os.environ.get("EMULATOR_HOST", "emulator")
EMULATOR_ADB_PORT = int(os.environ.get("EMULATOR_ADB_PORT", "5555"))
EMULATOR_FRIDA_PORT = int(os.environ.get("EMULATOR_FRIDA_PORT", "27042"))
MITMPROXY_HOST = os.environ.get("MITMPROXY_HOST", "mitmproxy")
MITMPROXY_API_PORT = int(os.environ.get("MITMPROXY_API_PORT", "8081"))
DEFAULT_TIMEOUT = int(os.environ.get("DYNAMIC_TIMEOUT", "120"))

# ---------------------------------------------------------------------------
# Frida instrumentation scripts (JavaScript injected at runtime)
# ---------------------------------------------------------------------------

_FRIDA_NETWORK_SCRIPT = r"""
(function() {
  // Hook OkHttp3 / HttpURLConnection for HTTP/HTTPS requests
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
      var conn = this.openConnection();
      send(JSON.stringify({
        type: 'network',
        subtype: 'http_connection',
        url: this.toString(),
        timestamp: Date.now()
      }));
      return conn;
    };
  } catch(e) {}

  // Hook InetAddress DNS resolution
  try {
    var InetAddress = Java.use('java.net.InetAddress');
    InetAddress.getByName.overload('java.lang.String').implementation = function(host) {
      send(JSON.stringify({
        type: 'network',
        subtype: 'dns_lookup',
        host: host,
        timestamp: Date.now()
      }));
      return this.getByName(host);
    };
  } catch(e) {}

  // Hook Socket creation for raw TCP connections
  try {
    var Socket = Java.use('java.net.Socket');
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
      send(JSON.stringify({
        type: 'network',
        subtype: 'raw_socket',
        host: host,
        port: port,
        timestamp: Date.now()
      }));
      this.$init(host, port);
    };
  } catch(e) {}
})();
"""

_FRIDA_FILESYSTEM_SCRIPT = r"""
(function() {
  // Hook FileOutputStream for writes
  try {
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
      send(JSON.stringify({
        type: 'filesystem',
        subtype: 'file_write',
        path: path,
        timestamp: Date.now()
      }));
      this.$init(path);
    };
    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
      send(JSON.stringify({
        type: 'filesystem',
        subtype: 'file_write',
        path: file.getAbsolutePath(),
        timestamp: Date.now()
      }));
      this.$init(file);
    };
  } catch(e) {}

  // Hook SharedPreferences writes
  try {
    var SharedPreferencesEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    SharedPreferencesEditor.putString.implementation = function(key, value) {
      send(JSON.stringify({
        type: 'filesystem',
        subtype: 'shared_prefs_write',
        key: key,
        timestamp: Date.now()
      }));
      return this.putString(key, value);
    };
  } catch(e) {}
})();
"""

_FRIDA_CRYPTO_SCRIPT = r"""
(function() {
  // Hook Cipher encryption/decryption
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
      var mode = this.getAlgorithm();
      send(JSON.stringify({
        type: 'crypto',
        subtype: 'cipher_operation',
        algorithm: mode,
        input_length: input ? input.length : 0,
        timestamp: Date.now()
      }));
      return this.doFinal(input);
    };
  } catch(e) {}

  // Hook KeyGenerator key generation
  try {
    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    KeyGenerator.generateKey.implementation = function() {
      var algorithm = this.getAlgorithm();
      send(JSON.stringify({
        type: 'crypto',
        subtype: 'key_generation',
        algorithm: algorithm,
        timestamp: Date.now()
      }));
      return this.generateKey();
    };
  } catch(e) {}

  // Hook MessageDigest for hashing
  try {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(input) {
      send(JSON.stringify({
        type: 'crypto',
        subtype: 'digest',
        algorithm: this.getAlgorithm(),
        timestamp: Date.now()
      }));
      return this.digest(input);
    };
  } catch(e) {}
})();
"""

_FRIDA_TELEPHONY_SCRIPT = r"""
(function() {
  // Hook SmsManager for SMS sending
  try {
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.implementation = function(destAddr, scAddr, text, sentIntent, deliveryIntent) {
      send(JSON.stringify({
        type: 'telephony',
        subtype: 'sms_send',
        destination: destAddr,
        timestamp: Date.now()
      }));
      this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
    };
  } catch(e) {}

  // Hook TelephonyManager for device ID reads
  try {
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.overload().implementation = function() {
      send(JSON.stringify({
        type: 'telephony',
        subtype: 'device_id_read',
        timestamp: Date.now()
      }));
      return this.getDeviceId();
    };
    TelephonyManager.getSubscriberId.implementation = function() {
      send(JSON.stringify({
        type: 'telephony',
        subtype: 'imsi_read',
        timestamp: Date.now()
      }));
      return this.getSubscriberId();
    };
  } catch(e) {}
})();
"""

_FRIDA_CONTENT_PROVIDER_SCRIPT = r"""
(function() {
  // Hook ContentResolver queries
  try {
    var ContentResolver = Java.use('android.content.ContentResolver');
    ContentResolver.query.overload(
      'android.net.Uri',
      '[Ljava.lang.String;',
      'java.lang.String',
      '[Ljava.lang.String;',
      'java.lang.String'
    ).implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
      var uriStr = uri ? uri.toString() : 'null';
      send(JSON.stringify({
        type: 'content_provider',
        subtype: 'query',
        uri: uriStr,
        timestamp: Date.now()
      }));
      return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };
  } catch(e) {}
})();
"""

_FRIDA_DYNAMIC_CODE_SCRIPT = r"""
(function() {
  // Hook DexClassLoader for dynamic code loading
  try {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, librarySearchPath, parent) {
      send(JSON.stringify({
        type: 'dynamic_code',
        subtype: 'dex_class_loader',
        dex_path: dexPath,
        timestamp: Date.now()
      }));
      this.$init(dexPath, optimizedDir, librarySearchPath, parent);
    };
  } catch(e) {}

  // Hook Class.forName for reflection
  try {
    var Class = Java.use('java.lang.Class');
    Class.forName.overload('java.lang.String').implementation = function(className) {
      if (!className.startsWith('java.') && !className.startsWith('android.') && !className.startsWith('com.google.')) {
        send(JSON.stringify({
          type: 'dynamic_code',
          subtype: 'reflection',
          class_name: className,
          timestamp: Date.now()
        }));
      }
      return Class.forName(className);
    };
  } catch(e) {}
})();
"""

COMBINED_FRIDA_SCRIPT = "\n".join([
    "Java.perform(function() {",
    _FRIDA_NETWORK_SCRIPT,
    _FRIDA_FILESYSTEM_SCRIPT,
    _FRIDA_CRYPTO_SCRIPT,
    _FRIDA_TELEPHONY_SCRIPT,
    _FRIDA_CONTENT_PROVIDER_SCRIPT,
    _FRIDA_DYNAMIC_CODE_SCRIPT,
    "});",
])

# ---------------------------------------------------------------------------
# Suspicious pattern rules for dynamic events
# ---------------------------------------------------------------------------

@dataclass
class DynamicRule:
    rule_id: str
    description: str
    severity: Severity
    category: str


_NETWORK_RULES: dict[str, DynamicRule] = {
    "suspicious_raw_socket": DynamicRule(
        rule_id="DYN_NET_001",
        description="App opened raw TCP socket to non-standard port — possible C2 communication",
        severity="high",
        category="spyware",
    ),
    "cleartext_http": DynamicRule(
        rule_id="DYN_NET_002",
        description="App transmitted data over unencrypted HTTP — sensitive data exposure risk",
        severity="medium",
        category="data_collection",
    ),
    "excessive_dns_lookups": DynamicRule(
        rule_id="DYN_NET_003",
        description="Excessive DNS lookups detected — possible DGA or ad-tracking behaviour",
        severity="low",
        category="spyware",
    ),
}

_FILESYSTEM_RULES: dict[str, DynamicRule] = {
    "external_storage_write": DynamicRule(
        rule_id="DYN_FS_001",
        description="App wrote files to external storage — potential data exfiltration staging",
        severity="medium",
        category="data_collection",
    ),
    "shared_prefs_sensitive": DynamicRule(
        rule_id="DYN_FS_002",
        description="App stored sensitive keys in SharedPreferences — insecure credential storage",
        severity="high",
        category="data_collection",
    ),
}

_CRYPTO_RULES: dict[str, DynamicRule] = {
    "weak_cipher": DynamicRule(
        rule_id="DYN_CRYPTO_001",
        description="App used weak cipher (DES/RC4/ECB mode) — insecure cryptographic practice",
        severity="high",
        category="spyware",
    ),
    "key_generation_at_runtime": DynamicRule(
        rule_id="DYN_CRYPTO_002",
        description="App generated cryptographic keys at runtime — potential ransomware behaviour",
        severity="high",
        category="ransomware",
    ),
}

_TELEPHONY_RULES: dict[str, DynamicRule] = {
    "sms_send": DynamicRule(
        rule_id="DYN_TEL_001",
        description="App sent SMS during runtime — potential premium SMS fraud",
        severity="critical",
        category="billing_fraud",
    ),
    "device_id_read": DynamicRule(
        rule_id="DYN_TEL_002",
        description="App read device IMEI/IMSI — potential device fingerprinting / spyware",
        severity="high",
        category="spyware",
    ),
}

_CONTENT_PROVIDER_RULES: dict[str, DynamicRule] = {
    "contacts_query": DynamicRule(
        rule_id="DYN_CP_001",
        description="App queried contacts content provider at runtime — potential contact harvesting",
        severity="high",
        category="spyware",
    ),
    "sms_query": DynamicRule(
        rule_id="DYN_CP_002",
        description="App queried SMS content provider at runtime — potential message exfiltration",
        severity="critical",
        category="spyware",
    ),
    "call_log_query": DynamicRule(
        rule_id="DYN_CP_003",
        description="App queried call log content provider at runtime — call record harvesting",
        severity="high",
        category="spyware",
    ),
}

_DYNAMIC_CODE_RULES: dict[str, DynamicRule] = {
    "dex_class_loader": DynamicRule(
        rule_id="DYN_CODE_001",
        description="App loaded DEX bytecode at runtime (DexClassLoader) — hostile downloader pattern",
        severity="critical",
        category="hostile_downloader",
    ),
    "suspicious_reflection": DynamicRule(
        rule_id="DYN_CODE_002",
        description="App used reflection to load unknown classes at runtime — potential code obfuscation",
        severity="medium",
        category="trojan",
    ),
}

# ---------------------------------------------------------------------------
# Emulator / ADB helpers
# ---------------------------------------------------------------------------

def _adb(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run an adb command targeting the configured emulator."""
    target = f"{EMULATOR_HOST}:{EMULATOR_ADB_PORT}"
    cmd = ["adb", "-H", EMULATOR_HOST, "-P", str(EMULATOR_ADB_PORT), "-s", target] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _wait_for_emulator(timeout: int = 60) -> bool:
    """Poll until the emulator ADB port is reachable or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((EMULATOR_HOST, EMULATOR_ADB_PORT), timeout=2):
                # Give ADB daemon a moment to stabilise
                time.sleep(2)
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(3)
    return False


def _wait_for_frida_server(timeout: int = 30) -> bool:
    """Poll until Frida server TCP port is open."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((EMULATOR_HOST, EMULATOR_FRIDA_PORT), timeout=2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(2)
    return False


def _install_apk(apk_path: str) -> bool:
    result = _adb(["install", "-r", "-t", apk_path], timeout=60)
    if result.returncode != 0:
        logger.error("[DynamicAnalyzer] APK install failed: %s", result.stderr)
        return False
    return True


def _get_package_name(apk_path: str) -> str | None:
    """Extract package name from APK using aapt."""
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                for part in line.split():
                    if part.startswith("name="):
                        return part.split("=", 1)[1].strip("'")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _launch_app(package_name: str) -> bool:
    """Launch the app's main activity via monkey."""
    result = _adb(
        ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        timeout=30,
    )
    return result.returncode == 0


def _stop_app(package_name: str) -> None:
    _adb(["shell", "am", "force-stop", package_name], timeout=10)


def _uninstall_apk(package_name: str) -> None:
    _adb(["uninstall", package_name], timeout=30)

# ---------------------------------------------------------------------------
# mitmproxy traffic capture
# ---------------------------------------------------------------------------

def _fetch_mitmproxy_flows() -> list[dict[str, Any]]:
    """Retrieve captured HTTP flows from the mitmproxy REST API."""
    try:
        import urllib.request
        url = f"http://{MITMPROXY_HOST}:{MITMPROXY_API_PORT}/flows"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())  # type: ignore[return-value]
    except Exception as exc:
        logger.warning("[DynamicAnalyzer] Could not fetch mitmproxy flows: %s", exc)
        return []


def _clear_mitmproxy_flows() -> None:
    try:
        import urllib.request
        req = urllib.request.Request(
            f"http://{MITMPROXY_HOST}:{MITMPROXY_API_PORT}/clear",
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def _analyze_traffic_flows(flows: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    http_urls: list[str] = []
    http_count = 0

    for flow in flows:
        try:
            req = flow.get("request", {})
            scheme = req.get("scheme", "")
            host = req.get("host", "")
            path = req.get("path", "/")
            url = f"{scheme}://{host}{path}"

            if scheme == "http":
                http_urls.append(url)
                http_count += 1

            # Log all intercepted HTTPS as informational findings
            if scheme == "https":
                findings.append(Finding(
                    category="data_collection",
                    severity="low",
                    rule="DYN_TRAFFIC_001",
                    description=f"Intercepted HTTPS traffic to {host}",
                    evidence=url[:200],
                ))
        except Exception:
            continue

    if http_count > 0:
        rule = _NETWORK_RULES["cleartext_http"]
        findings.append(Finding(
            category=rule.category,
            severity=rule.severity,
            rule=rule.rule_id,
            description=rule.description,
            evidence="; ".join(http_urls[:5]),
        ))

    return findings

# ---------------------------------------------------------------------------
# Frida session management
# ---------------------------------------------------------------------------

def _run_frida_session(
    package_name: str,
    timeout: int,
) -> list[dict[str, Any]]:
    """
    Attach Frida to the running app, inject instrumentation scripts,
    and collect events until timeout.

    Returns a list of raw event dicts received via Frida messages.
    """
    events: list[dict[str, Any]] = []

    try:
        import frida  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("[DynamicAnalyzer] frida package not installed — skipping instrumentation")
        return events

    try:
        device_manager = frida.get_device_manager()
        device = device_manager.add_remote_device(f"{EMULATOR_HOST}:{EMULATOR_FRIDA_PORT}")
        session = device.attach(package_name)

        script = session.create_script(COMBINED_FRIDA_SCRIPT)

        def on_message(message: dict[str, Any], _data: Any) -> None:
            if message.get("type") == "send":
                try:
                    payload = json.loads(message["payload"])
                    payload["_raw_ts"] = time.time()
                    events.append(payload)
                except (json.JSONDecodeError, KeyError):
                    pass
            elif message.get("type") == "error":
                logger.debug("[DynamicAnalyzer] Frida script error: %s", message.get("description"))

        script.on("message", on_message)
        script.load()

        logger.info("[DynamicAnalyzer] Frida instrumentation active for %s; running for %ds", package_name, timeout)
        time.sleep(timeout)

        script.unload()
        session.detach()
    except Exception as exc:
        logger.error("[DynamicAnalyzer] Frida session error: %s", exc)

    return events

# ---------------------------------------------------------------------------
# Event → Finding conversion
# ---------------------------------------------------------------------------

def _events_to_findings(events: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    # Aggregate counts
    dns_count = 0
    raw_socket_ports: list[int] = []
    external_writes: list[str] = []
    sensitive_pref_keys: list[str] = []

    SENSITIVE_PREF_KEYWORDS = {"password", "token", "secret", "key", "auth", "credential", "api_key"}
    SENSITIVE_CP_HOSTS = {
        "content://contacts": "contacts_query",
        "content://com.android.contacts": "contacts_query",
        "content://sms": "sms_query",
        "content://mms-sms": "sms_query",
        "content://call_log": "call_log_query",
    }
    WEAK_CIPHERS = {"DES", "RC4", "ARCFOUR", "Blowfish", "DES/ECB", "AES/ECB"}

    def _emit(rule: DynamicRule, evidence: str = "") -> None:
        if rule.rule_id not in seen_rules:
            seen_rules.add(rule.rule_id)
            findings.append(Finding(
                category=rule.category,
                severity=rule.severity,
                rule=rule.rule_id,
                description=rule.description,
                evidence=evidence,
            ))

    for evt in events:
        etype = evt.get("type")
        subtype = evt.get("subtype", "")

        if etype == "network":
            if subtype == "dns_lookup":
                dns_count += 1
            elif subtype == "raw_socket":
                port = evt.get("port", 0)
                if port not in (80, 443, 8080, 8443):
                    raw_socket_ports.append(port)
            elif subtype == "http_connection":
                url = evt.get("url", "")
                if url.startswith("http://"):
                    _emit(_NETWORK_RULES["cleartext_http"], evidence=url[:200])

        elif etype == "filesystem":
            if subtype == "file_write":
                path = evt.get("path", "")
                if "/sdcard/" in path or "/external_storage/" in path or "/storage/emulated/" in path:
                    external_writes.append(path)
            elif subtype == "shared_prefs_write":
                key = evt.get("key", "").lower()
                if any(kw in key for kw in SENSITIVE_PREF_KEYWORDS):
                    sensitive_pref_keys.append(evt.get("key", ""))

        elif etype == "crypto":
            if subtype == "cipher_operation":
                alg = evt.get("algorithm", "")
                if any(w in alg.upper() for w in WEAK_CIPHERS):
                    _emit(_CRYPTO_RULES["weak_cipher"], evidence=alg)
            elif subtype == "key_generation":
                _emit(_CRYPTO_RULES["key_generation_at_runtime"], evidence=evt.get("algorithm", ""))

        elif etype == "telephony":
            if subtype == "sms_send":
                _emit(_TELEPHONY_RULES["sms_send"], evidence=f"destination={evt.get('destination', 'unknown')}")
            elif subtype in ("device_id_read", "imsi_read"):
                _emit(_TELEPHONY_RULES["device_id_read"])

        elif etype == "content_provider":
            uri = evt.get("uri", "")
            for prefix, rule_key in SENSITIVE_CP_HOSTS.items():
                if uri.startswith(prefix):
                    _emit(_CONTENT_PROVIDER_RULES[rule_key], evidence=uri[:200])
                    break

        elif etype == "dynamic_code":
            if subtype == "dex_class_loader":
                _emit(_DYNAMIC_CODE_RULES["dex_class_loader"], evidence=evt.get("dex_path", ""))
            elif subtype == "reflection":
                _emit(_DYNAMIC_CODE_RULES["suspicious_reflection"], evidence=evt.get("class_name", ""))

    # Deferred / aggregate checks
    if dns_count > 50:
        _emit(_NETWORK_RULES["excessive_dns_lookups"], evidence=f"{dns_count} DNS queries in session")

    if raw_socket_ports:
        _emit(
            _NETWORK_RULES["suspicious_raw_socket"],
            evidence=f"ports: {', '.join(str(p) for p in raw_socket_ports[:10])}",
        )

    if external_writes:
        _emit(
            _FILESYSTEM_RULES["external_storage_write"],
            evidence="; ".join(external_writes[:5]),
        )

    if sensitive_pref_keys:
        _emit(
            _FILESYSTEM_RULES["shared_prefs_sensitive"],
            evidence=f"keys: {', '.join(sensitive_pref_keys[:5])}",
        )

    return findings

# ---------------------------------------------------------------------------
# Dynamic risk score delta
# ---------------------------------------------------------------------------

_DYNAMIC_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 3,
}


def compute_dynamic_risk_delta(findings: list[Finding]) -> int:
    """
    Compute additional risk score contribution from dynamic findings.
    Dynamic findings are weighted 1.5× compared to static findings.
    """
    base = sum(_DYNAMIC_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return int(base * 1.5)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class DynamicAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    events_captured: int = 0
    traffic_flows_captured: int = 0
    timeout_seconds: int = DEFAULT_TIMEOUT
    package_name: str = ""
    error: str | None = None


def analyze_apk_dynamic(apk_path: str, timeout: int = DEFAULT_TIMEOUT) -> DynamicAnalysisResult:
    """
    Run dynamic analysis on an APK file.

    Orchestrates the emulator, Frida instrumentation, and mitmproxy.
    Returns a DynamicAnalysisResult with findings.

    Raises FileNotFoundError if the APK does not exist.
    """
    from pathlib import Path
    if not Path(apk_path).exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    result = DynamicAnalysisResult(timeout_seconds=timeout)

    # 1. Extract package name
    package_name = _get_package_name(apk_path)
    if not package_name:
        logger.warning("[DynamicAnalyzer] Could not determine package name; using stub")
        package_name = "com.unknown.app"
    result.package_name = package_name
    logger.info("[DynamicAnalyzer] Package name: %s", package_name)

    # 2. Wait for emulator to be ready
    logger.info("[DynamicAnalyzer] Waiting for emulator at %s:%d ...", EMULATOR_HOST, EMULATOR_ADB_PORT)
    if not _wait_for_emulator(timeout=90):
        result.error = f"Emulator not reachable at {EMULATOR_HOST}:{EMULATOR_ADB_PORT}"
        logger.error("[DynamicAnalyzer] %s", result.error)
        return result

    # 3. Wait for Frida server
    logger.info("[DynamicAnalyzer] Waiting for Frida server on port %d ...", EMULATOR_FRIDA_PORT)
    if not _wait_for_frida_server(timeout=30):
        result.error = f"Frida server not reachable on port {EMULATOR_FRIDA_PORT}"
        logger.error("[DynamicAnalyzer] %s", result.error)
        return result

    # 4. Clear previous mitmproxy flows
    _clear_mitmproxy_flows()

    # 5. Install APK
    logger.info("[DynamicAnalyzer] Installing APK ...")
    if not _install_apk(apk_path):
        result.error = "APK installation failed"
        return result

    try:
        # 6. Launch app
        logger.info("[DynamicAnalyzer] Launching %s ...", package_name)
        if not _launch_app(package_name):
            logger.warning("[DynamicAnalyzer] App launch may have failed; continuing anyway")

        # Small delay to allow app to initialise
        time.sleep(3)

        # 7. Run Frida instrumentation session
        events = _run_frida_session(package_name, timeout=timeout)
        result.events_captured = len(events)
        logger.info("[DynamicAnalyzer] Captured %d Frida events", len(events))

        # 8. Fetch mitmproxy traffic
        flows = _fetch_mitmproxy_flows()
        result.traffic_flows_captured = len(flows)
        logger.info("[DynamicAnalyzer] Captured %d traffic flows", len(flows))

        # 9. Convert to findings
        frida_findings = _events_to_findings(events)
        traffic_findings = _analyze_traffic_flows(flows)
        result.findings = frida_findings + traffic_findings

        logger.info(
            "[DynamicAnalyzer] Dynamic analysis complete: %d findings",
            len(result.findings),
        )

    finally:
        # 10. Cleanup: stop and uninstall app
        logger.info("[DynamicAnalyzer] Stopping and uninstalling %s ...", package_name)
        _stop_app(package_name)
        _uninstall_apk(package_name)

    return result
