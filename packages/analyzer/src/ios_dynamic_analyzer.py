"""
iOS Dynamic Analysis via Frida instrumentation on Xcode Simulator.

Orchestrates:
  1. Xcode Simulator (xcrun simctl) selection and boot
  2. IPA extraction and app installation
  3. Frida-based runtime hooks for iOS:
     - Network calls (NSURLSession, CFNetwork, raw sockets)
     - Keychain access (SecItemAdd, SecItemCopyMatching, SecItemDelete)
     - Pasteboard/clipboard (UIPasteboard)
     - Location access (CLLocationManager)
     - Contacts access (CNContactStore)
     - Crypto operations (CommonCrypto CCCrypt, Security framework SecKey*)
  4. mitmproxy for TLS traffic interception
  5. Aggregates dynamic findings and integrates with risk scoring

Environment variables:
  IOS_SIMULATOR_UDID   - UDID of simulator to use; auto-selected if unset
  IOS_FRIDA_PORT       - Frida server port on simulator host (default: 27042)
  MITMPROXY_HOST       - hostname for mitmproxy (default: mitmproxy)
  MITMPROXY_API_PORT   - mitmproxy HTTP API port (default: 8081)
  IOS_DYNAMIC_TIMEOUT  - seconds before analysis is terminated (default: 120)

Requirements:
  - macOS host with Xcode + Simulator runtime installed
  - frida and frida-tools pip packages
  - mitmproxy (optional; traffic capture degrades gracefully without it)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IOS_SIMULATOR_UDID = os.environ.get("IOS_SIMULATOR_UDID", "")
IOS_FRIDA_PORT = int(os.environ.get("IOS_FRIDA_PORT", "27042"))
MITMPROXY_HOST = os.environ.get("MITMPROXY_HOST", "mitmproxy")
MITMPROXY_API_PORT = int(os.environ.get("MITMPROXY_API_PORT", "8081"))
DEFAULT_TIMEOUT = int(os.environ.get("IOS_DYNAMIC_TIMEOUT", "120"))

# ---------------------------------------------------------------------------
# Frida instrumentation scripts (ObjC/Swift hooks for iOS)
# ---------------------------------------------------------------------------

_FRIDA_IOS_NETWORK_SCRIPT = r"""
(function() {
  // Hook NSURLSession dataTaskWithRequest for HTTP/HTTPS traffic
  try {
    var NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
      var dataTaskMethod = NSURLSession['- dataTaskWithRequest:completionHandler:'];
      if (dataTaskMethod) {
        Interceptor.attach(dataTaskMethod.implementation, {
          onEnter: function(args) {
            try {
              var req = new ObjC.Object(args[2]);
              var url = req.URL().absoluteString().toString();
              send(JSON.stringify({
                type: 'network',
                subtype: 'nsurlsession_request',
                url: url,
                method: req.HTTPMethod().toString(),
                timestamp: Date.now()
              }));
            } catch(e) {}
          }
        });
      }
    }
  } catch(e) {}

  // Hook CFStreamCreatePairWithSocketToHost for raw TCP connections
  try {
    var cfStreamPtr = Module.findExportByName('CFNetwork', 'CFStreamCreatePairWithSocketToHost');
    if (cfStreamPtr) {
      Interceptor.attach(cfStreamPtr, {
        onEnter: function(args) {
          try {
            var host = new ObjC.Object(args[1]).toString();
            var port = args[2].toInt32();
            send(JSON.stringify({
              type: 'network',
              subtype: 'raw_socket',
              host: host,
              port: port,
              timestamp: Date.now()
            }));
          } catch(e) {}
        }
      });
    }
  } catch(e) {}

  // Hook getaddrinfo for DNS lookups
  try {
    var getaddrinfo = Module.findExportByName(null, 'getaddrinfo');
    if (getaddrinfo) {
      Interceptor.attach(getaddrinfo, {
        onEnter: function(args) {
          try {
            var host = args[0].readUtf8String();
            if (host) {
              send(JSON.stringify({
                type: 'network',
                subtype: 'dns_lookup',
                host: host,
                timestamp: Date.now()
              }));
            }
          } catch(e) {}
        }
      });
    }
  } catch(e) {}
})();
"""

_FRIDA_IOS_KEYCHAIN_SCRIPT = r"""
(function() {
  // Hook SecItemAdd — storing items in the keychain
  try {
    var secItemAdd = Module.findExportByName('Security', 'SecItemAdd');
    if (secItemAdd) {
      Interceptor.attach(secItemAdd, {
        onEnter: function(args) {
          try {
            var query = new ObjC.Object(args[0]);
            var desc = query.description().toString().substring(0, 300);
            send(JSON.stringify({
              type: 'keychain',
              subtype: 'item_add',
              query_desc: desc,
              timestamp: Date.now()
            }));
          } catch(e) {}
        }
      });
    }
  } catch(e) {}

  // Hook SecItemCopyMatching — reading from the keychain
  try {
    var secItemCopy = Module.findExportByName('Security', 'SecItemCopyMatching');
    if (secItemCopy) {
      Interceptor.attach(secItemCopy, {
        onEnter: function(args) {
          try {
            var query = new ObjC.Object(args[0]);
            var desc = query.description().toString().substring(0, 300);
            send(JSON.stringify({
              type: 'keychain',
              subtype: 'item_read',
              query_desc: desc,
              timestamp: Date.now()
            }));
          } catch(e) {}
        }
      });
    }
  } catch(e) {}

  // Hook SecItemDelete — deleting keychain items (possible anti-forensics)
  try {
    var secItemDelete = Module.findExportByName('Security', 'SecItemDelete');
    if (secItemDelete) {
      Interceptor.attach(secItemDelete, {
        onEnter: function(args) {
          try {
            send(JSON.stringify({
              type: 'keychain',
              subtype: 'item_delete',
              timestamp: Date.now()
            }));
          } catch(e) {}
        }
      });
    }
  } catch(e) {}
})();
"""

_FRIDA_IOS_PASTEBOARD_SCRIPT = r"""
(function() {
  // Hook UIPasteboard setString: — writing to clipboard
  try {
    var UIPasteboard = ObjC.classes.UIPasteboard;
    if (UIPasteboard) {
      var setString = UIPasteboard['- setString:'];
      if (setString) {
        Interceptor.attach(setString.implementation, {
          onEnter: function(args) {
            try {
              var value = new ObjC.Object(args[2]).toString().substring(0, 200);
              send(JSON.stringify({
                type: 'pasteboard',
                subtype: 'write',
                value_preview: value,
                timestamp: Date.now()
              }));
            } catch(e) {}
          }
        });
      }
      // Hook string getter — reading from clipboard
      var getString = UIPasteboard['- string'];
      if (getString) {
        Interceptor.attach(getString.implementation, {
          onEnter: function(args) {
            send(JSON.stringify({
              type: 'pasteboard',
              subtype: 'read',
              timestamp: Date.now()
            }));
          }
        });
      }
    }
  } catch(e) {}
})();
"""

_FRIDA_IOS_LOCATION_SCRIPT = r"""
(function() {
  // Hook CLLocationManager startUpdatingLocation
  try {
    var CLLocationManager = ObjC.classes.CLLocationManager;
    if (CLLocationManager) {
      var startUpdating = CLLocationManager['- startUpdatingLocation'];
      if (startUpdating) {
        Interceptor.attach(startUpdating.implementation, {
          onEnter: function(args) {
            send(JSON.stringify({
              type: 'location',
              subtype: 'start_updates',
              timestamp: Date.now()
            }));
          }
        });
      }
      var requestWhenInUse = CLLocationManager['- requestWhenInUseAuthorization'];
      if (requestWhenInUse) {
        Interceptor.attach(requestWhenInUse.implementation, {
          onEnter: function(args) {
            send(JSON.stringify({
              type: 'location',
              subtype: 'request_authorization',
              level: 'when_in_use',
              timestamp: Date.now()
            }));
          }
        });
      }
      var requestAlways = CLLocationManager['- requestAlwaysAuthorization'];
      if (requestAlways) {
        Interceptor.attach(requestAlways.implementation, {
          onEnter: function(args) {
            send(JSON.stringify({
              type: 'location',
              subtype: 'request_authorization',
              level: 'always',
              timestamp: Date.now()
            }));
          }
        });
      }
    }
  } catch(e) {}
})();
"""

_FRIDA_IOS_CONTACTS_SCRIPT = r"""
(function() {
  // Hook CNContactStore enumerateContactsWithFetchRequest
  try {
    var CNContactStore = ObjC.classes.CNContactStore;
    if (CNContactStore) {
      var enumerate = CNContactStore['- enumerateContactsWithFetchRequest:error:usingBlock:'];
      if (enumerate) {
        Interceptor.attach(enumerate.implementation, {
          onEnter: function(args) {
            send(JSON.stringify({
              type: 'contacts',
              subtype: 'enumerate',
              timestamp: Date.now()
            }));
          }
        });
      }
      var requestAccess = CNContactStore['- requestAccessForEntityType:completionHandler:'];
      if (requestAccess) {
        Interceptor.attach(requestAccess.implementation, {
          onEnter: function(args) {
            send(JSON.stringify({
              type: 'contacts',
              subtype: 'request_access',
              timestamp: Date.now()
            }));
          }
        });
      }
    }
  } catch(e) {}
})();
"""

_FRIDA_IOS_CRYPTO_SCRIPT = r"""
(function() {
  // Hook CCCrypt (CommonCrypto) — bulk encryption/decryption
  try {
    var cccrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
    if (!cccrypt) cccrypt = Module.findExportByName(null, 'CCCrypt');
    if (cccrypt) {
      Interceptor.attach(cccrypt, {
        onEnter: function(args) {
          try {
            // args[0] = operation (0=encrypt, 1=decrypt)
            // args[1] = algorithm (0=AES, 1=DES, 2=3DES, 3=CAST, 4=RC4, 5=RC2, 6=Blowfish)
            var op = args[0].toInt32();
            var alg = args[1].toInt32();
            var algNames = ['AES', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'Blowfish'];
            var algName = algNames[alg] || 'Unknown(' + alg + ')';
            send(JSON.stringify({
              type: 'crypto',
              subtype: 'cccrypt',
              operation: op === 0 ? 'encrypt' : 'decrypt',
              algorithm: algName,
              timestamp: Date.now()
            }));
          } catch(e) {}
        }
      });
    }
  } catch(e) {}

  // Hook CCKeyDerivationPBKDF — PBKDF2 key derivation
  try {
    var pbkdf = Module.findExportByName(null, 'CCKeyDerivationPBKDF');
    if (pbkdf) {
      Interceptor.attach(pbkdf, {
        onEnter: function(args) {
          send(JSON.stringify({
            type: 'crypto',
            subtype: 'key_derivation_pbkdf',
            timestamp: Date.now()
          }));
        }
      });
    }
  } catch(e) {}

  // Hook SecKeyCreateEncryptedData — Security framework asymmetric encryption
  try {
    var secKeyEncrypt = Module.findExportByName('Security', 'SecKeyCreateEncryptedData');
    if (secKeyEncrypt) {
      Interceptor.attach(secKeyEncrypt, {
        onEnter: function(args) {
          send(JSON.stringify({
            type: 'crypto',
            subtype: 'seckey_encrypt',
            timestamp: Date.now()
          }));
        }
      });
    }
  } catch(e) {}

  // Hook SecKeyGeneratePair — asymmetric key generation
  try {
    var secKeyGenPair = Module.findExportByName('Security', 'SecKeyGeneratePair');
    if (secKeyGenPair) {
      Interceptor.attach(secKeyGenPair, {
        onEnter: function(args) {
          send(JSON.stringify({
            type: 'crypto',
            subtype: 'key_generation_asymmetric',
            timestamp: Date.now()
          }));
        }
      });
    }
  } catch(e) {}
})();
"""

COMBINED_IOS_FRIDA_SCRIPT = "\n".join([
    "ObjC.schedule(ObjC.mainQueue, function() {",
    _FRIDA_IOS_NETWORK_SCRIPT,
    _FRIDA_IOS_KEYCHAIN_SCRIPT,
    _FRIDA_IOS_PASTEBOARD_SCRIPT,
    _FRIDA_IOS_LOCATION_SCRIPT,
    _FRIDA_IOS_CONTACTS_SCRIPT,
    _FRIDA_IOS_CRYPTO_SCRIPT,
    "});",
])

# ---------------------------------------------------------------------------
# Suspicious pattern rules for iOS dynamic events
# ---------------------------------------------------------------------------

@dataclass
class DynamicRule:
    rule_id: str
    description: str
    severity: Severity
    category: str


_IOS_NETWORK_RULES: dict[str, DynamicRule] = {
    "suspicious_raw_socket": DynamicRule(
        rule_id="IOS_DYN_NET_001",
        description="App opened raw TCP socket to non-standard port — possible C2 communication",
        severity="high",
        category="spyware",
    ),
    "cleartext_http": DynamicRule(
        rule_id="IOS_DYN_NET_002",
        description="App transmitted data over unencrypted HTTP — ATS bypass or data exposure risk",
        severity="medium",
        category="data_collection",
    ),
    "excessive_dns_lookups": DynamicRule(
        rule_id="IOS_DYN_NET_003",
        description="Excessive DNS lookups detected — possible DGA or ad-tracking behaviour",
        severity="low",
        category="spyware",
    ),
}

_IOS_KEYCHAIN_RULES: dict[str, DynamicRule] = {
    "keychain_write": DynamicRule(
        rule_id="IOS_DYN_KC_001",
        description="App wrote sensitive data to Keychain at runtime — credential or token storage",
        severity="low",
        category="data_collection",
    ),
    "keychain_read_sensitive": DynamicRule(
        rule_id="IOS_DYN_KC_002",
        description="App read from Keychain — potential credential access or token exfiltration",
        severity="medium",
        category="spyware",
    ),
    "keychain_delete": DynamicRule(
        rule_id="IOS_DYN_KC_003",
        description="App deleted Keychain items — possible anti-forensics behaviour",
        severity="medium",
        category="trojan",
    ),
}

_IOS_PASTEBOARD_RULES: dict[str, DynamicRule] = {
    "pasteboard_read": DynamicRule(
        rule_id="IOS_DYN_PB_001",
        description="App read from system pasteboard — potential clipboard snooping",
        severity="high",
        category="spyware",
    ),
    "pasteboard_write": DynamicRule(
        rule_id="IOS_DYN_PB_002",
        description="App wrote to system pasteboard — potential data staging for exfiltration",
        severity="medium",
        category="data_collection",
    ),
}

_IOS_LOCATION_RULES: dict[str, DynamicRule] = {
    "location_tracking": DynamicRule(
        rule_id="IOS_DYN_LOC_001",
        description="App started location updates at runtime — real-time location tracking",
        severity="high",
        category="spyware",
    ),
    "location_always_auth": DynamicRule(
        rule_id="IOS_DYN_LOC_002",
        description="App requested Always location authorization — persistent background location access",
        severity="high",
        category="spyware",
    ),
}

_IOS_CONTACTS_RULES: dict[str, DynamicRule] = {
    "contacts_access": DynamicRule(
        rule_id="IOS_DYN_CONT_001",
        description="App enumerated device contacts at runtime — potential contact harvesting",
        severity="high",
        category="spyware",
    ),
}

_IOS_CRYPTO_RULES: dict[str, DynamicRule] = {
    "weak_cipher_des": DynamicRule(
        rule_id="IOS_DYN_CRYPTO_001",
        description="App used DES or RC4 cipher (CommonCrypto) — insecure cryptographic practice",
        severity="high",
        category="spyware",
    ),
    "key_generation_asymmetric": DynamicRule(
        rule_id="IOS_DYN_CRYPTO_002",
        description="App generated asymmetric key pair at runtime — potential ransomware behaviour",
        severity="high",
        category="ransomware",
    ),
}

# ---------------------------------------------------------------------------
# Simulator helpers (xcrun simctl)
# ---------------------------------------------------------------------------

def _simctl(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    cmd = ["xcrun", "simctl"] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _find_booted_simulator() -> str | None:
    """Return UDID of a booted simulator if one exists."""
    result = _simctl(["list", "devices", "booted", "--json"])
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
        for _runtime, devices in data.get("devices", {}).items():
            for dev in devices:
                if dev.get("state") == "Booted":
                    return dev["udid"]
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _find_available_simulator() -> str | None:
    """Return UDID of the first available iPhone simulator runtime."""
    result = _simctl(["list", "devices", "available", "--json"])
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
        for runtime, devices in data.get("devices", {}).items():
            # Prefer recent iOS runtimes
            if "iOS" not in runtime:
                continue
            for dev in devices:
                if dev.get("isAvailable", False) and "iPhone" in dev.get("name", ""):
                    return dev["udid"]
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _boot_simulator(udid: str, timeout: int = 90) -> bool:
    result = _simctl(["boot", udid], timeout=30)
    if result.returncode not in (0, 149):  # 149 = already booted
        logger.error("[iOSDynamic] simctl boot failed: %s", result.stderr.strip())
        return False

    # Wait for Booted state
    deadline = time.time() + timeout
    while time.time() < deadline:
        check = _simctl(["list", "devices", udid, "--json"])
        try:
            data = json.loads(check.stdout)
            for devices in data.get("devices", {}).values():
                for dev in devices:
                    if dev.get("udid") == udid and dev.get("state") == "Booted":
                        return True
        except (json.JSONDecodeError, KeyError):
            pass
        time.sleep(3)
    return False


def _shutdown_simulator(udid: str) -> None:
    _simctl(["shutdown", udid], timeout=15)


def _extract_app_from_ipa(ipa_path: str, work_dir: str) -> tuple[str | None, str | None]:
    """
    Extract the .app bundle from an IPA file and return (app_bundle_path, bundle_id).
    IPA structure: Payload/<AppName>.app/
    """
    try:
        with zipfile.ZipFile(ipa_path, "r") as z:
            app_entry = next(
                (n for n in z.namelist() if n.startswith("Payload/") and n.endswith(".app/")),
                None,
            )
            if not app_entry:
                # Try without trailing slash
                app_entry = next(
                    (n + "/" for n in z.namelist() if n.startswith("Payload/") and n.endswith(".app")),
                    None,
                )
            if not app_entry:
                logger.error("[iOSDynamic] No .app bundle found in IPA")
                return None, None

            z.extractall(work_dir)

        app_path = Path(work_dir) / Path(app_entry)
        if not app_path.exists():
            # Find it via glob
            matches = list(Path(work_dir).glob("Payload/*.app"))
            if not matches:
                return None, None
            app_path = matches[0]

        bundle_id = _read_bundle_id(str(app_path))
        return str(app_path), bundle_id

    except (zipfile.BadZipFile, StopIteration, Exception) as exc:
        logger.error("[iOSDynamic] IPA extraction failed: %s", exc)
        return None, None


def _read_bundle_id(app_path: str) -> str | None:
    """Read CFBundleIdentifier from the app's Info.plist."""
    info_plist = Path(app_path) / "Info.plist"
    if not info_plist.exists():
        return None
    try:
        result = subprocess.run(
            ["plutil", "-p", str(info_plist)],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "CFBundleIdentifier" in line:
                # "CFBundleIdentifier" => "com.example.app"
                parts = line.split("=>")
                if len(parts) >= 2:
                    return parts[1].strip().strip('"')
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _install_app(udid: str, app_path: str) -> bool:
    result = _simctl(["install", udid, app_path], timeout=60)
    if result.returncode != 0:
        logger.error("[iOSDynamic] App install failed: %s", result.stderr.strip())
        return False
    return True


def _launch_app(udid: str, bundle_id: str) -> bool:
    result = _simctl(["launch", udid, bundle_id], timeout=30)
    if result.returncode != 0:
        logger.warning("[iOSDynamic] App launch may have failed: %s", result.stderr.strip())
        return False
    return True


def _terminate_app(udid: str, bundle_id: str) -> None:
    _simctl(["terminate", udid, bundle_id], timeout=10)


def _uninstall_app(udid: str, bundle_id: str) -> None:
    _simctl(["uninstall", udid, bundle_id], timeout=30)


def _wait_for_frida_port(timeout: int = 30) -> bool:
    """Poll until Frida USB/TCP bridge is accessible on the simulator host."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", IOS_FRIDA_PORT), timeout=2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(2)
    return False

# ---------------------------------------------------------------------------
# mitmproxy traffic capture (same helper as Android dynamic analyzer)
# ---------------------------------------------------------------------------

def _fetch_mitmproxy_flows() -> list[dict[str, Any]]:
    try:
        import urllib.request
        url = f"http://{MITMPROXY_HOST}:{MITMPROXY_API_PORT}/flows"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())  # type: ignore[return-value]
    except Exception as exc:
        logger.debug("[iOSDynamic] Could not fetch mitmproxy flows: %s", exc)
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

    for flow in flows:
        try:
            req = flow.get("request", {})
            scheme = req.get("scheme", "")
            host = req.get("host", "")
            path = req.get("path", "/")
            url = f"{scheme}://{host}{path}"

            if scheme == "http":
                http_urls.append(url)

            if scheme == "https":
                findings.append(Finding(
                    category="data_collection",
                    severity="low",
                    rule="IOS_DYN_TRAFFIC_001",
                    description=f"Intercepted HTTPS traffic to {host}",
                    evidence=url[:200],
                ))
        except Exception:
            continue

    if http_urls:
        rule = _IOS_NETWORK_RULES["cleartext_http"]
        findings.append(Finding(
            category=rule.category,
            severity=rule.severity,
            rule=rule.rule_id,
            description=rule.description,
            evidence="; ".join(http_urls[:5]),
        ))

    return findings

# ---------------------------------------------------------------------------
# Frida session for iOS simulator
# ---------------------------------------------------------------------------

def _run_frida_ios_session(
    bundle_id: str,
    timeout: int,
) -> list[dict[str, Any]]:
    """
    Attach Frida to the running iOS app in the simulator, inject instrumentation
    scripts, and collect events until timeout.
    """
    events: list[dict[str, Any]] = []

    try:
        import frida  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("[iOSDynamic] frida package not installed — skipping instrumentation")
        return events

    try:
        # For iOS simulator, Frida connects via USB (simulated USB)
        device = frida.get_usb_device(timeout=10)
        session = device.attach(bundle_id)

        script = session.create_script(COMBINED_IOS_FRIDA_SCRIPT)

        def on_message(message: dict[str, Any], _data: Any) -> None:
            if message.get("type") == "send":
                try:
                    payload = json.loads(message["payload"])
                    payload["_raw_ts"] = time.time()
                    events.append(payload)
                except (json.JSONDecodeError, KeyError):
                    pass
            elif message.get("type") == "error":
                logger.debug("[iOSDynamic] Frida script error: %s", message.get("description"))

        script.on("message", on_message)
        script.load()

        logger.info("[iOSDynamic] Frida instrumentation active for %s; running for %ds", bundle_id, timeout)
        time.sleep(timeout)

        script.unload()
        session.detach()

    except Exception as exc:
        logger.error("[iOSDynamic] Frida session error: %s", exc)

    return events

# ---------------------------------------------------------------------------
# Event → Finding conversion
# ---------------------------------------------------------------------------

def _events_to_findings(events: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    seen_rules: set[str] = set()

    dns_count = 0
    raw_socket_ports: list[int] = []
    keychain_reads = 0
    keychain_writes = 0

    WEAK_ALGOS = {"DES", "RC4", "RC2"}

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
            elif subtype == "nsurlsession_request":
                url = evt.get("url", "")
                if url.startswith("http://"):
                    _emit(_IOS_NETWORK_RULES["cleartext_http"], evidence=url[:200])

        elif etype == "keychain":
            if subtype == "item_add":
                keychain_writes += 1
                _emit(_IOS_KEYCHAIN_RULES["keychain_write"])
            elif subtype == "item_read":
                keychain_reads += 1
                _emit(_IOS_KEYCHAIN_RULES["keychain_read_sensitive"])
            elif subtype == "item_delete":
                _emit(_IOS_KEYCHAIN_RULES["keychain_delete"])

        elif etype == "pasteboard":
            if subtype == "read":
                _emit(_IOS_PASTEBOARD_RULES["pasteboard_read"])
            elif subtype == "write":
                _emit(_IOS_PASTEBOARD_RULES["pasteboard_write"])

        elif etype == "location":
            if subtype == "start_updates":
                _emit(_IOS_LOCATION_RULES["location_tracking"])
            elif subtype == "request_authorization" and evt.get("level") == "always":
                _emit(_IOS_LOCATION_RULES["location_always_auth"])

        elif etype == "contacts":
            if subtype in ("enumerate", "request_access"):
                _emit(_IOS_CONTACTS_RULES["contacts_access"])

        elif etype == "crypto":
            if subtype == "cccrypt":
                alg = evt.get("algorithm", "")
                if any(w in alg.upper() for w in WEAK_ALGOS):
                    _emit(_IOS_CRYPTO_RULES["weak_cipher_des"], evidence=alg)
            elif subtype in ("key_generation_asymmetric", "key_derivation_pbkdf"):
                _emit(_IOS_CRYPTO_RULES["key_generation_asymmetric"])

    # Aggregate checks
    if dns_count > 50:
        _emit(_IOS_NETWORK_RULES["excessive_dns_lookups"], evidence=f"{dns_count} DNS queries in session")

    if raw_socket_ports:
        _emit(
            _IOS_NETWORK_RULES["suspicious_raw_socket"],
            evidence=f"ports: {', '.join(str(p) for p in raw_socket_ports[:10])}",
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


def compute_ios_dynamic_risk_delta(findings: list[Finding]) -> int:
    """Compute additional risk score contribution from iOS dynamic findings (1.5× weight)."""
    base = sum(_DYNAMIC_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return int(base * 1.5)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class IosDynamicAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    events_captured: int = 0
    traffic_flows_captured: int = 0
    timeout_seconds: int = DEFAULT_TIMEOUT
    bundle_id: str = ""
    simulator_udid: str = ""
    error: str | None = None


def analyze_ipa_dynamic(ipa_path: str, timeout: int = DEFAULT_TIMEOUT) -> IosDynamicAnalysisResult:
    """
    Run dynamic analysis on an IPA file using the iOS Simulator + Frida.

    Steps:
      1. Select/boot a simulator
      2. Extract .app from IPA
      3. Install and launch the app
      4. Run Frida instrumentation for `timeout` seconds
      5. Collect mitmproxy traffic
      6. Clean up

    Raises FileNotFoundError if ipa_path does not exist.
    Requires macOS + Xcode + Simulator runtime.
    """
    if not Path(ipa_path).exists():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")

    result = IosDynamicAnalysisResult(timeout_seconds=timeout)
    work_dir = tempfile.mkdtemp(prefix="ios_dynamic_")

    try:
        # 1. Resolve simulator UDID
        udid = IOS_SIMULATOR_UDID or _find_booted_simulator() or _find_available_simulator()
        if not udid:
            result.error = "No suitable iOS simulator found. Install Xcode and at least one iOS runtime."
            logger.error("[iOSDynamic] %s", result.error)
            return result

        result.simulator_udid = udid
        logger.info("[iOSDynamic] Using simulator UDID: %s", udid)

        # 2. Boot simulator if needed
        logger.info("[iOSDynamic] Booting simulator ...")
        if not _boot_simulator(udid, timeout=90):
            result.error = f"Failed to boot simulator {udid}"
            logger.error("[iOSDynamic] %s", result.error)
            return result

        # 3. Extract .app from IPA
        logger.info("[iOSDynamic] Extracting IPA ...")
        app_path, bundle_id = _extract_app_from_ipa(ipa_path, work_dir)
        if not app_path or not bundle_id:
            result.error = "Failed to extract .app bundle or read bundle ID from IPA"
            logger.error("[iOSDynamic] %s", result.error)
            return result

        result.bundle_id = bundle_id
        logger.info("[iOSDynamic] Bundle ID: %s  App path: %s", bundle_id, app_path)

        # 4. Clear previous mitmproxy flows
        _clear_mitmproxy_flows()

        # 5. Install app
        logger.info("[iOSDynamic] Installing app on simulator ...")
        if not _install_app(udid, app_path):
            result.error = "App installation on simulator failed"
            return result

        try:
            # 6. Launch app
            logger.info("[iOSDynamic] Launching %s ...", bundle_id)
            _launch_app(udid, bundle_id)
            time.sleep(3)  # Allow app to initialise

            # 7. Run Frida instrumentation
            events = _run_frida_ios_session(bundle_id, timeout=timeout)
            result.events_captured = len(events)
            logger.info("[iOSDynamic] Captured %d Frida events", len(events))

            # 8. Fetch mitmproxy traffic
            flows = _fetch_mitmproxy_flows()
            result.traffic_flows_captured = len(flows)
            logger.info("[iOSDynamic] Captured %d traffic flows", len(flows))

            # 9. Convert events and traffic to findings
            frida_findings = _events_to_findings(events)
            traffic_findings = _analyze_traffic_flows(flows)
            result.findings = frida_findings + traffic_findings

            logger.info(
                "[iOSDynamic] Analysis complete: %d findings (%d frida + %d traffic)",
                len(result.findings),
                len(frida_findings),
                len(traffic_findings),
            )

        finally:
            # 10. Cleanup
            logger.info("[iOSDynamic] Terminating and uninstalling %s ...", bundle_id)
            _terminate_app(udid, bundle_id)
            _uninstall_app(udid, bundle_id)

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    return result
