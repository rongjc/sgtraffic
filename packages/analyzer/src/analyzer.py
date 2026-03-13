"""
Main APK analysis orchestrator.
Coordinates all analysis modules and produces a final AnalysisResult.
"""
import hashlib
from dataclasses import asdict
from pathlib import Path

from .models import AnalysisResult, ApkMetadata, Finding
from .permissions import analyze_permissions
from .manifest_analysis import analyze_manifest
from .dex_analysis import analyze_dex
from .cert_analysis import analyze_certificates
from .string_analysis import analyze_strings


def analyze_apk(apk_path: str) -> dict:
    """
    Analyze an APK file and return a JSON-serializable result dict.
    Raises FileNotFoundError if the APK doesn't exist.
    """
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    # Parse the APK with androguard
    apk_obj, dex_list, dx = _load_apk(apk_path)

    result = AnalysisResult()
    result.metadata = _extract_metadata(apk_path, apk_obj)

    findings: list[Finding] = []

    # 1. Permission analysis
    findings.extend(analyze_permissions(result.metadata.permissions))

    # 2. Manifest analysis
    if apk_obj is not None:
        findings.extend(analyze_manifest(apk_obj))

    # 3. DEX / code analysis
    if dx is not None:
        findings.extend(analyze_dex(dx))
        findings.extend(analyze_strings(dx))

    # 4. Certificate analysis
    if apk_obj is not None:
        findings.extend(analyze_certificates(apk_obj))

    result.findings = findings
    result.pha_categories = list({f.category for f in findings})
    result.risk_score = _compute_risk_score(findings)
    result.verdict = _determine_verdict(result.risk_score, result.pha_categories)

    return _to_dict(result)


def _load_apk(apk_path: str):
    """
    Load an APK with androguard. Returns (apk_obj, dex_list, analysis).
    Falls back gracefully so partial results can still be returned.
    """
    try:
        from androguard.misc import AnalyzeAPK
        apk_obj, dex_list, dx = AnalyzeAPK(apk_path)
        return apk_obj, dex_list, dx
    except Exception:
        try:
            from androguard.core.bytecodes.apk import APK
            apk_obj = APK(apk_path)
            return apk_obj, None, None
        except Exception:
            return None, None, None


def _extract_metadata(apk_path: str, apk_obj) -> ApkMetadata:
    sha256 = _sha256(apk_path)

    if apk_obj is None:
        return ApkMetadata(sha256=sha256)

    try:
        package_name = apk_obj.get_package() or "unknown"
    except Exception:
        package_name = "unknown"

    try:
        version = apk_obj.get_androidversion_name() or "unknown"
    except Exception:
        version = "unknown"

    try:
        min_sdk = int(apk_obj.get_min_sdk_version() or 0)
    except Exception:
        min_sdk = 0

    try:
        target_sdk = int(apk_obj.get_target_sdk_version() or 0)
    except Exception:
        target_sdk = 0

    try:
        permissions = list(apk_obj.get_permissions()) or []
    except Exception:
        permissions = []

    return ApkMetadata(
        package_name=package_name,
        version=version,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=permissions,
        sha256=sha256,
    )


def _compute_risk_score(findings: list[Finding]) -> int:
    severity_weights = {"critical": 30, "high": 15, "medium": 8, "low": 3}
    score = sum(severity_weights.get(f.severity, 0) for f in findings)
    return min(score, 100)


def _determine_verdict(risk_score: int, categories: list[str]) -> str:
    # Hard PHA categories always flag as pha regardless of score
    hard_pha = {
        "backdoor", "ransomware", "rooting", "trojan", "spyware",
        "commercial_spyware", "hostile_downloader", "privilege_escalation",
    }
    if any(c in hard_pha for c in categories):
        return "pha"
    if risk_score >= 60:
        return "pha"
    if risk_score >= 25:
        return "suspicious"
    return "clean"


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _to_dict(result: AnalysisResult) -> dict:
    d = asdict(result)
    return {
        "verdict": d["verdict"],
        "risk_score": d["risk_score"],
        "pha_categories": d["pha_categories"],
        "findings": d["findings"],
        "metadata": d["metadata"],
    }
