"""
Web API fuzzing module.

Supports three input modes:
  1. Standalone (OpenAPI/Swagger spec) — parse spec, enumerate endpoints, fuzz them.
  2. Traffic (HAR file) — extract endpoints from captured mitmproxy/browser traffic.
  3. Endpoint list — fuzz a manually supplied list of endpoint dicts.

Detects:
  - SQL injection (error-based)
  - SSRF (response-based and timing-based)
  - Stack-trace / information disclosure
  - Excessive data exposure (sensitive field names in responses)
  - Authentication bypass (401/403 → 200 with tampered auth headers)
"""

import json
import re
import time
import warnings
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress only the InsecureRequestWarning when verify=False
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from .models import Finding


# ─────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────

@dataclass
class ApiEndpoint:
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    body: Optional[dict] = None
    auth_required: bool = False


@dataclass
class HttpInteraction:
    """A captured request/response pair used as finding evidence."""
    request_method: str
    request_url: str
    request_headers: dict
    request_body: str
    response_status: int
    response_headers: dict
    response_body: str
    duration_ms: float = 0.0


# ─────────────────────────────────────────────────────────────────
# Payload library
# ─────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "admin'--",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/admin",
    "file:///etc/passwd",
    "http://[::1]/",
]

AUTH_BYPASS_HEADERS = [
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"Authorization": ""},
    {"X-User-Id": "1"},
    {"X-Admin": "true"},
    {"X-Forwarded-For": "127.0.0.1"},
]


# ─────────────────────────────────────────────────────────────────
# Detection patterns
# ─────────────────────────────────────────────────────────────────

_SQLI_ERRORS = [
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"pg_query",
    r"Unclosed quotation",
    r"sqlite.*error",
    r"syntax error.*query",
    r"You have an error in your SQL",
]

_SSRF_INDICATORS = [
    r"ami-id",
    r"instance-id",
    r"169\.254\.",
    r"root:[x*]:0:0",
    r"local-ipv4",
    r"hostname",
]

_STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [A-Za-z]+\.[A-Za-z]+\(",
    r"java\.lang\.",
    r"NullPointerException",
    r"StackOverflowError",
    r"Exception in thread",
    r"SyntaxError:",
    r"TypeError:",
]

_SENSITIVE_FIELD_PATTERNS = [
    r'"password"\s*:',
    r'"passwd"\s*:',
    r'"token"\s*:',
    r'"secret"\s*:',
    r'"api_key"\s*:',
    r'"private_key"\s*:',
    r'"credit_card"\s*:',
    r'"ssn"\s*:',
    r'"auth_token"\s*:',
]


# ─────────────────────────────────────────────────────────────────
# Spec parsers
# ─────────────────────────────────────────────────────────────────

def parse_openapi_spec(spec: dict) -> list[ApiEndpoint]:
    """
    Parse an OpenAPI 3.x or Swagger 2.x spec into ApiEndpoint objects.
    """
    endpoints: list[ApiEndpoint] = []

    # Base URL
    if "openapi" in spec:  # OpenAPI 3.x
        servers = spec.get("servers") or [{}]
        base_url = servers[0].get("url", "").rstrip("/")
    else:  # Swagger 2.x
        host = spec.get("host", "localhost")
        base_path = spec.get("basePath", "/").rstrip("/")
        scheme = (spec.get("schemes") or ["https"])[0]
        base_url = f"{scheme}://{host}{base_path}"

    paths = spec.get("paths") or {}
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in http_methods:
            op = path_item.get(method)
            if op is None:
                continue

            full_url = base_url + path
            params: dict = {}
            body: Optional[dict] = None
            auth_required = bool(op.get("security") or spec.get("security"))

            # Query parameters
            for param in op.get("parameters") or []:
                if param.get("in") == "query":
                    name = param.get("name", "")
                    schema = param.get("schema") or {}
                    default = schema.get("default")
                    params[name] = str(default) if default is not None else "test"

            # Request body (OpenAPI 3.x)
            if "requestBody" in op:
                content = op["requestBody"].get("content") or {}
                json_content = content.get("application/json") or {}
                schema = json_content.get("schema") or {}
                body = _sample_body_from_schema(schema)

            # Request body (Swagger 2.x)
            for param in op.get("parameters") or []:
                if param.get("in") == "body" and body is None:
                    body = _sample_body_from_schema(param.get("schema") or {})

            endpoints.append(ApiEndpoint(
                url=full_url,
                method=method.upper(),
                params=params,
                body=body,
                auth_required=auth_required,
            ))

    return endpoints


def parse_har_traffic(har: dict) -> list[ApiEndpoint]:
    """
    Extract unique API endpoints from a HAR (HTTP Archive) file.
    Compatible with mitmproxy's HAR export and browser DevTools format.
    """
    seen: set[str] = set()
    endpoints: list[ApiEndpoint] = []

    entries = (har.get("log") or {}).get("entries") or []
    for entry in entries:
        req = entry.get("request") or {}
        method = req.get("method", "GET").upper()
        url = req.get("url", "")

        key = f"{method}:{url}"
        if key in seen:
            continue
        seen.add(key)

        params = {p["name"]: p.get("value", "") for p in req.get("queryString") or []}
        headers = {h["name"]: h["value"] for h in req.get("headers") or []}

        body: Optional[dict] = None
        post_data = req.get("postData") or {}
        mime = post_data.get("mimeType", "")
        text = post_data.get("text", "")
        if "json" in mime and text:
            try:
                body = json.loads(text)
            except Exception:
                pass

        endpoints.append(ApiEndpoint(
            url=url,
            method=method,
            params=params,
            headers=headers,
            body=body,
        ))

    return endpoints


def _sample_body_from_schema(schema: dict) -> Optional[dict]:
    """Generate a minimal sample body dict from a JSON Schema object."""
    if not schema or schema.get("type") != "object":
        return None
    body: dict = {}
    for name, prop in (schema.get("properties") or {}).items():
        prop_type = prop.get("type", "string")
        if prop_type == "string":
            body[name] = "test"
        elif prop_type in ("integer", "number"):
            body[name] = 1
        elif prop_type == "boolean":
            body[name] = True
        elif prop_type == "array":
            body[name] = []
        elif prop_type == "object":
            body[name] = {}
    return body or None


# ─────────────────────────────────────────────────────────────────
# HTTP client
# ─────────────────────────────────────────────────────────────────

def _make_session() -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(total=0))
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "ApkMalwareScanner/1.0 (API Security Audit)",
        "Accept": "application/json",
    })
    return session


def _send(
    session: requests.Session,
    method: str,
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    body: Optional[dict] = None,
    timeout: int = 10,
) -> HttpInteraction:
    t0 = time.monotonic()
    try:
        resp = session.request(
            method=method,
            url=url,
            params=params or {},
            headers=headers or {},
            json=body,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        duration_ms = (time.monotonic() - t0) * 1000
        try:
            resp_body = resp.text[:4096]
        except Exception:
            resp_body = ""
        return HttpInteraction(
            request_method=method,
            request_url=resp.request.url or url,
            request_headers=dict(resp.request.headers),
            request_body=str(resp.request.body or ""),
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp_body,
            duration_ms=duration_ms,
        )
    except requests.exceptions.Timeout:
        return HttpInteraction(
            request_method=method, request_url=url,
            request_headers={}, request_body="",
            response_status=0, response_headers={},
            response_body="[timed out]",
            duration_ms=(time.monotonic() - t0) * 1000,
        )
    except Exception as exc:
        return HttpInteraction(
            request_method=method, request_url=url,
            request_headers={}, request_body="",
            response_status=0, response_headers={},
            response_body=f"[error: {exc}]",
            duration_ms=0.0,
        )


# ─────────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────────

def _evidence(interaction: HttpInteraction, max_body: int = 500) -> str:
    return (
        f"Request:  {interaction.request_method} {interaction.request_url}\n"
        f"Response: {interaction.response_status}\n"
        f"Body:     {interaction.response_body[:max_body]}"
    )


def _detect_sqli(ix: HttpInteraction) -> Optional[Finding]:
    for pat in _SQLI_ERRORS:
        if re.search(pat, ix.response_body, re.IGNORECASE):
            return Finding(
                category="injection",
                severity="high",
                rule="api_sqli_error",
                description=(
                    "Server returned a SQL error message in response to an injection "
                    "payload, indicating a potential SQL injection vulnerability."
                ),
                evidence=_evidence(ix),
            )
    return None


def _detect_ssrf_response(ix: HttpInteraction) -> Optional[Finding]:
    for pat in _SSRF_INDICATORS:
        if re.search(pat, ix.response_body, re.IGNORECASE):
            return Finding(
                category="ssrf",
                severity="critical",
                rule="api_ssrf_detected",
                description=(
                    "SSRF vulnerability confirmed: server returned internal/metadata "
                    "content in response to an SSRF probe payload."
                ),
                evidence=_evidence(ix),
            )
    return None


def _detect_ssrf_timing(ix: HttpInteraction) -> Optional[Finding]:
    if ix.response_status == 0 and ix.duration_ms > 4500:
        return Finding(
            category="ssrf",
            severity="medium",
            rule="api_ssrf_timing",
            description=(
                "Possible SSRF: endpoint timed out on an SSRF probe, suggesting an "
                "outbound connection attempt to the injected URL."
            ),
            evidence=(
                f"Request:  {ix.request_method} {ix.request_url}\n"
                f"Duration: {ix.duration_ms:.0f}ms"
            ),
        )
    return None


def _detect_stack_trace(ix: HttpInteraction) -> Optional[Finding]:
    for pat in _STACK_TRACE_PATTERNS:
        if re.search(pat, ix.response_body, re.IGNORECASE):
            return Finding(
                category="data_collection",
                severity="medium",
                rule="api_stack_trace_exposure",
                description=(
                    "API endpoint leaked a stack trace or internal error message, "
                    "exposing server implementation details."
                ),
                evidence=_evidence(ix),
            )
    return None


def _detect_sensitive_data(ix: HttpInteraction) -> Optional[Finding]:
    for pat in _SENSITIVE_FIELD_PATTERNS:
        if re.search(pat, ix.response_body, re.IGNORECASE):
            return Finding(
                category="data_collection",
                severity="high",
                rule="api_excessive_data_exposure",
                description=(
                    "API response contains sensitive field names (passwords, tokens, "
                    "secrets), indicating possible excessive data exposure."
                ),
                evidence=_evidence(ix),
            )
    return None


def _detect_auth_bypass(baseline_status: int, ix: HttpInteraction) -> Optional[Finding]:
    if baseline_status in (401, 403) and ix.response_status == 200:
        auth_val = ix.request_headers.get("Authorization", "n/a")
        return Finding(
            category="backdoor",
            severity="critical",
            rule="api_auth_bypass",
            description=(
                "Possible authentication bypass: endpoint returned HTTP 200 with a "
                "tampered Authorization header that should have been rejected."
            ),
            evidence=(
                f"Endpoint:      {ix.request_method} {ix.request_url}\n"
                f"Auth header:   {auth_val}\n"
                f"Baseline status: {baseline_status} → Fuzz status: {ix.response_status}"
            ),
        )
    return None


def _looks_like_url_param(name: str) -> bool:
    return any(
        kw in name.lower()
        for kw in ["url", "uri", "endpoint", "host", "redirect", "callback",
                   "target", "src", "href", "link", "next", "return"]
    )


# ─────────────────────────────────────────────────────────────────
# Core fuzzer
# ─────────────────────────────────────────────────────────────────

class ApiFuzzer:
    """
    Fuzzes a list of ApiEndpoint objects and returns a de-duplicated
    list of security Finding objects.
    """

    def __init__(
        self,
        timeout: int = 10,
        max_endpoints: int = 50,
        extra_headers: Optional[dict] = None,
    ):
        self.timeout = timeout
        self.max_endpoints = max_endpoints
        self.extra_headers = extra_headers or {}
        self._session = _make_session()

    def fuzz(self, endpoints: list[ApiEndpoint]) -> list[Finding]:
        all_findings: list[Finding] = []
        seen: set[str] = set()

        for ep in endpoints[:self.max_endpoints]:
            for f in self._fuzz_endpoint(ep):
                key = f"{f.rule}:{ep.url}"
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

        return all_findings

    def _fuzz_endpoint(self, ep: ApiEndpoint) -> list[Finding]:
        findings: list[Finding] = []
        merged_hdrs = {**ep.headers, **self.extra_headers}

        # ── Baseline ──────────────────────────────────────────────
        baseline = _send(self._session, ep.method, ep.url,
                         params=ep.params, headers=merged_hdrs,
                         body=ep.body, timeout=self.timeout)

        # Check baseline for sensitive data / stack traces
        self._collect(findings, _detect_sensitive_data(baseline))
        self._collect(findings, _detect_stack_trace(baseline))

        # ── SQL injection ─────────────────────────────────────────
        for payload in SQLI_PAYLOADS[:2]:
            fuzz_params = {k: payload for k in (ep.params or {"q": ""})}
            fuzz_body = {k: payload for k in ep.body} if ep.body else None

            ix = _send(self._session, ep.method, ep.url,
                       params=fuzz_params, headers=merged_hdrs,
                       body=fuzz_body, timeout=self.timeout)
            self._collect(findings, _detect_sqli(ix))
            self._collect(findings, _detect_stack_trace(ix))

        # ── SSRF ──────────────────────────────────────────────────
        for payload in SSRF_PAYLOADS[:2]:
            # Inject into URL-like params; fall back to adding a 'url' param
            fuzz_params = {}
            for k, v in (ep.params or {}).items():
                fuzz_params[k] = payload if _looks_like_url_param(k) else v
            if not fuzz_params or not any(_looks_like_url_param(k) for k in fuzz_params):
                fuzz_params["url"] = payload

            fuzz_body: Optional[dict] = None
            if ep.body:
                fuzz_body = {
                    k: payload if _looks_like_url_param(k) else v
                    for k, v in ep.body.items()
                }
                if not any(_looks_like_url_param(k) for k in ep.body):
                    fuzz_body["url"] = payload

            ix = _send(self._session, ep.method, ep.url,
                       params=fuzz_params, headers=merged_hdrs,
                       body=fuzz_body, timeout=self.timeout)
            self._collect(findings, _detect_ssrf_response(ix))
            self._collect(findings, _detect_ssrf_timing(ix))

        # ── Auth bypass ───────────────────────────────────────────
        for bypass in AUTH_BYPASS_HEADERS[:3]:
            ix = _send(self._session, ep.method, ep.url,
                       params=ep.params,
                       headers={**merged_hdrs, **bypass},
                       body=ep.body, timeout=self.timeout)
            self._collect(findings, _detect_auth_bypass(baseline.response_status, ix))

        return findings

    @staticmethod
    def _collect(acc: list[Finding], f: Optional[Finding]) -> None:
        if f is not None:
            acc.append(f)


# ─────────────────────────────────────────────────────────────────
# Mitmproxy capture helper
# ─────────────────────────────────────────────────────────────────

def capture_traffic_via_proxy(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    duration_sec: int = 60,
    output_har: str = "/tmp/captured.har",
) -> dict:
    """
    Launch mitmproxy in the background, wait for `duration_sec`, then dump
    the captured traffic as a HAR dict.

    Requires `mitmproxy` to be installed (`pip install mitmproxy`).
    The caller is responsible for routing traffic through the proxy
    (e.g. by setting HTTPS_PROXY=http://127.0.0.1:8080 in the target app).

    Returns:
        HAR dict suitable for parse_har_traffic().

    Raises:
        RuntimeError if mitmproxy is not installed.
    """
    try:
        import subprocess
        import tempfile
        import os
    except ImportError:
        raise RuntimeError("subprocess/os not available")

    try:
        import mitmproxy  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "mitmproxy is not installed. Install it with: pip install mitmproxy"
        )

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as addon_f:
        addon_f.write(
            f"""
import json, time
from mitmproxy import http, ctx

ENTRIES = []
START = time.time()
DURATION = {duration_sec}

def response(flow: http.HTTPFlow):
    req = flow.request
    resp = flow.response
    entry = {{
        "request": {{
            "method": req.method,
            "url": req.pretty_url,
            "headers": [
                {{"name": k, "value": v}} for k, v in req.headers.items()
            ],
            "queryString": [
                {{"name": k, "value": v}} for k, v in req.query.items()
            ],
            "postData": {{
                "mimeType": req.headers.get("content-type", ""),
                "text": req.get_text(strict=False) or "",
            }},
        }},
        "response": {{
            "status": resp.status_code,
            "headers": [
                {{"name": k, "value": v}} for k, v in resp.headers.items()
            ],
            "content": {{
                "mimeType": resp.headers.get("content-type", ""),
                "text": resp.get_text(strict=False) or "",
            }},
        }},
    }}
    ENTRIES.append(entry)
    if time.time() - START >= DURATION:
        har = {{"log": {{"entries": ENTRIES}}}}
        with open("{output_har}", "w") as f:
            json.dump(har, f)
        ctx.master.shutdown()
"""
        )
        addon_path = addon_f.name

    try:
        proc = subprocess.Popen([
            "mitmdump",
            "--listen-host", proxy_host,
            "--listen-port", str(proxy_port),
            "--scripts", addon_path,
        ])
        proc.wait(timeout=duration_sec + 10)
    finally:
        try:
            proc.kill()
        except Exception:
            pass
        os.unlink(addon_path)

    if not os.path.exists(output_har):
        return {"log": {"entries": []}}

    with open(output_har) as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

def _to_dict(f: Finding) -> dict:
    return {
        "category": f.category,
        "severity": f.severity,
        "rule": f.rule,
        "description": f.description,
        "evidence": f.evidence,
    }


def fuzz_from_openapi(
    spec: dict,
    timeout: int = 10,
    max_endpoints: int = 50,
    extra_headers: Optional[dict] = None,
) -> list[dict]:
    """
    Fuzz endpoints described in an OpenAPI/Swagger spec dict.

    Args:
        spec:           Parsed OpenAPI/Swagger dict.
        timeout:        Per-request timeout in seconds.
        max_endpoints:  Cap on how many endpoints to test.
        extra_headers:  Headers added to every request (e.g. auth tokens).

    Returns:
        List of finding dicts with keys: category, severity, rule, description, evidence.
    """
    endpoints = parse_openapi_spec(spec)
    return [_to_dict(f) for f in
            ApiFuzzer(timeout=timeout, max_endpoints=max_endpoints,
                      extra_headers=extra_headers).fuzz(endpoints)]


def fuzz_from_har(
    har: dict,
    timeout: int = 10,
    max_endpoints: int = 50,
    extra_headers: Optional[dict] = None,
) -> list[dict]:
    """
    Fuzz endpoints extracted from a captured HAR traffic file.

    Args:
        har:            Parsed HAR dict (from mitmproxy export or browser DevTools).
        timeout:        Per-request timeout in seconds.
        max_endpoints:  Cap on how many endpoints to test.
        extra_headers:  Headers added to every request.

    Returns:
        List of finding dicts.
    """
    endpoints = parse_har_traffic(har)
    return [_to_dict(f) for f in
            ApiFuzzer(timeout=timeout, max_endpoints=max_endpoints,
                      extra_headers=extra_headers).fuzz(endpoints)]


def fuzz_from_endpoint_list(
    endpoints: list[dict],
    timeout: int = 10,
    max_endpoints: int = 50,
    extra_headers: Optional[dict] = None,
) -> list[dict]:
    """
    Fuzz a manually specified list of endpoints.

    Each endpoint dict may have:
        url (required), method, params, headers, body.

    Returns:
        List of finding dicts.
    """
    api_endpoints = [
        ApiEndpoint(
            url=e["url"],
            method=e.get("method", "GET").upper(),
            params=e.get("params") or {},
            headers=e.get("headers") or {},
            body=e.get("body"),
        )
        for e in endpoints
        if e.get("url")
    ]
    return [_to_dict(f) for f in
            ApiFuzzer(timeout=timeout, max_endpoints=max_endpoints,
                      extra_headers=extra_headers).fuzz(api_endpoints)]
