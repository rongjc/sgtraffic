"""
Certificate analysis — detects self-signed certs, debug certificates,
and certificate validity anomalies.
"""
import datetime
from .models import Finding


# Well-known debug certificate attributes
_DEBUG_CERT_SUBJECTS = [
    "cn=android debug",
    "o=android",
    "ou=android",
    "cn=unknown,ou=unknown,o=unknown",
]

# Unreasonably long validity (>30 years) or unreasonably short (<1 day)
_MAX_VALID_YEARS = 30
_MIN_VALID_DAYS = 1


def analyze_certificates(apk) -> list[Finding]:
    """
    Accepts an androguard APK object and returns certificate findings.
    """
    findings: list[Finding] = []
    try:
        certs = apk.get_certificates_der_v2() or []
        if not certs:
            # Fall back to v1 signatures
            certs = _get_v1_certs(apk)

        for cert_der in certs:
            try:
                findings.extend(_analyze_cert(cert_der))
            except Exception:
                pass
    except Exception:
        pass
    return findings


def _get_v1_certs(apk) -> list[bytes]:
    try:
        return list(apk.get_certificates_der_v1().values())
    except Exception:
        return []


def _analyze_cert(cert_der: bytes) -> list[Finding]:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    findings = []
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        return findings

    # Check self-signed
    try:
        issuer = cert.issuer.rfc4514_string().lower()
        subject = cert.subject.rfc4514_string().lower()
        if issuer == subject:
            findings.append(Finding(
                category="non_android_threat",
                severity="medium",
                rule="self_signed_cert",
                description="APK is signed with a self-signed certificate (issuer == subject). Legitimate apps from known developers use CA-signed or well-established self-signed certs, but this warrants attention.",
                evidence=f"Subject/Issuer: {cert.subject.rfc4514_string()}",
            ))
    except Exception:
        pass

    # Check debug certificate
    try:
        subject_lower = cert.subject.rfc4514_string().lower()
        if any(debug_marker in subject_lower for debug_marker in _DEBUG_CERT_SUBJECTS):
            findings.append(Finding(
                category="non_android_threat",
                severity="high",
                rule="debug_certificate",
                description="APK is signed with a debug certificate in a release build. Debug-signed apps are a sign of low quality or potentially trojanized builds.",
                evidence=f"Subject: {cert.subject.rfc4514_string()}",
            ))
    except Exception:
        pass

    # Check validity period
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        validity_days = (not_after - not_before).days

        if validity_days > _MAX_VALID_YEARS * 365:
            findings.append(Finding(
                category="non_android_threat",
                severity="low",
                rule="cert_validity_too_long",
                description=f"Certificate validity period is unusually long ({validity_days} days / ~{validity_days // 365} years). This is unusual for legitimate certificates.",
                evidence=f"Valid from {not_before.date()} to {not_after.date()}",
            ))

        if validity_days < _MIN_VALID_DAYS:
            findings.append(Finding(
                category="non_android_threat",
                severity="medium",
                rule="cert_validity_too_short",
                description=f"Certificate validity period is suspiciously short ({validity_days} days).",
                evidence=f"Valid from {not_before.date()} to {not_after.date()}",
            ))

        # Expired certificate
        if not_after < now:
            findings.append(Finding(
                category="non_android_threat",
                severity="medium",
                rule="cert_expired",
                description="APK is signed with an expired certificate.",
                evidence=f"Expired: {not_after.date()}",
            ))
    except Exception:
        pass

    return findings
