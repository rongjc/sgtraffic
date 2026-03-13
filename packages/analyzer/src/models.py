"""Shared data models for analysis results."""
from dataclasses import dataclass, field
from typing import Literal


Severity = Literal["critical", "high", "medium", "low"]
Verdict = Literal["pha", "clean", "suspicious"]
PhaCategory = Literal[
    "backdoor",
    "billing_fraud",
    "commercial_spyware",
    "denial_of_service",
    "hostile_downloader",
    "non_android_threat",
    "phishing",
    "privilege_escalation",
    "ransomware",
    "rooting",
    "spam",
    "spyware",
    "trojan",
    "wap_fraud",
    "data_collection",
]


@dataclass
class Finding:
    category: str
    severity: Severity
    rule: str
    description: str
    evidence: str = ""


@dataclass
class ApkMetadata:
    package_name: str = ""
    version: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list[str] = field(default_factory=list)
    sha256: str = ""


@dataclass
class AnalysisResult:
    verdict: Verdict = "clean"
    risk_score: int = 0
    pha_categories: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: ApkMetadata = field(default_factory=ApkMetadata)
