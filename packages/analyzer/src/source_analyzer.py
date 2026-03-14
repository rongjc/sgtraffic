"""
Source code analysis entry point.
Accepts a path to a .zip archive, extracts it to a temp directory,
auto-detects the project type (android_source or ios_source),
runs the appropriate analyzer, and returns a JSON-serializable result.
"""
import hashlib
import tempfile
import zipfile
from dataclasses import asdict
from pathlib import Path

from .models import AnalysisResult, Finding
from .analyzer import _compute_risk_score, _determine_verdict
from .android_source_analyzer import analyze_android_source
from .ios_source_analyzer import analyze_ios_source


# Sentinel file names used for project-type detection
ANDROID_INDICATORS = {"AndroidManifest.xml", "build.gradle", "build.gradle.kts", "settings.gradle"}
IOS_INDICATORS_EXTENSIONS = {".xcodeproj", ".xcworkspace"}
IOS_INDICATORS_FILES = {"Info.plist", "Podfile"}


def _detect_project_type(extracted_dir: Path) -> str | None:
    """
    Return 'android_source', 'ios_source', or None if unknown.
    Walks the top few levels of the extracted directory looking for indicator files.
    """
    all_names: set[str] = set()
    all_extensions: set[str] = set()

    # Walk up to 4 levels deep for efficiency
    for depth in range(4):
        glob_pattern = "/".join(["*"] * (depth + 1))
        for entry in extracted_dir.glob(glob_pattern):
            all_names.add(entry.name)
            all_extensions.add(entry.suffix)

    if ANDROID_INDICATORS & all_names:
        return "android_source"
    if IOS_INDICATORS_EXTENSIONS & all_extensions or IOS_INDICATORS_FILES & all_names:
        return "ios_source"
    return None


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze_source_zip(zip_path: str) -> dict:
    """
    Analyze a zipped Android or iOS source project.
    Returns a JSON-serializable dict with keys:
      verdict, risk_score, pha_categories, findings, metadata, source_type
    Raises FileNotFoundError if the zip doesn't exist.
    Raises ValueError if the project type cannot be determined.
    """
    path = Path(zip_path)
    if not path.exists():
        raise FileNotFoundError(f"Zip file not found: {zip_path}")

    sha256 = _sha256_file(zip_path)

    with tempfile.TemporaryDirectory() as tmp_dir:
        extracted = Path(tmp_dir) / "project"
        extracted.mkdir()

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Safety: strip absolute paths and path traversal
            for member in zf.infolist():
                member_path = Path(member.filename)
                # Skip absolute paths or paths trying to traverse above root
                if member_path.is_absolute() or ".." in member_path.parts:
                    continue
                dest = extracted / member_path
                if member.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(dest, "wb") as dst:
                        dst.write(src.read())

        source_type = _detect_project_type(extracted)
        if source_type is None:
            raise ValueError(
                "Cannot determine project type. "
                "Expected an Android (contains AndroidManifest.xml/build.gradle) "
                "or iOS (contains Info.plist/.xcodeproj/Podfile) project."
            )

        if source_type == "android_source":
            findings: list[Finding] = analyze_android_source(extracted)
        else:
            findings = analyze_ios_source(extracted)

    result = AnalysisResult()
    result.findings = findings
    result.pha_categories = list({f.category for f in findings})
    result.risk_score = _compute_risk_score(findings)
    result.verdict = _determine_verdict(result.risk_score, result.pha_categories)

    d = asdict(result)
    return {
        "verdict": d["verdict"],
        "risk_score": d["risk_score"],
        "pha_categories": d["pha_categories"],
        "findings": d["findings"],
        "metadata": {"sha256": sha256, "source_type": source_type},
        "source_type": source_type,
    }
