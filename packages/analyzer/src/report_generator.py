"""
PDF security report generation for APK/IPA scan results using ReportLab.
"""
from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Page geometry — A4 minus 2 cm left/right margins minus SimpleDocTemplate
# default frame left/right padding (6 pts each side).
_PAGE_W, _ = A4
_MARGIN = 2 * cm
_FRAME_PAD = 6  # SimpleDocTemplate default frame left/right padding
BODY_W = _PAGE_W - 2 * _MARGIN - 2 * _FRAME_PAD  # ≈ 469.89 pts


# ─────────────────────────────────────────────────────────────────
# Remediation knowledge base (rule → guidance text)
# ─────────────────────────────────────────────────────────────────
REMEDIATION: dict[str, str] = {
    # Permission combos
    "sms_internet_combo": (
        "Remove SEND_SMS permission unless SMS is core functionality. If required, add explicit user "
        "consent UI before any SMS is sent. Use Google Play Billing for premium features instead of toll-SMS."
    ),
    "receive_sms_internet_combo": (
        "Restrict RECEIVE_SMS to necessary message flows (e.g. OTP). Never transmit SMS content to "
        "remote servers without explicit user knowledge and consent. Use the SMS Retriever API instead."
    ),
    "camera_audio_internet_combo": (
        "Request CAMERA and RECORD_AUDIO permissions at the point of use, not at startup. Clearly "
        "document all remote transmission of audio/video data. Avoid background capture."
    ),
    "install_delete_packages_combo": (
        "Distribute app updates through Google Play only. If sideloading is required, implement "
        "cryptographic signature verification of downloaded packages before installation."
    ),
    "device_admin_internet_combo": (
        "Avoid device administrator APIs unless building an EMM/MDM solution. If required, document "
        "the use case clearly, target API 29+, and use Google Play Managed Configurations instead."
    ),
    "contacts_sms_internet_combo": (
        "Only collect contacts/SMS data with explicit user consent and a clear data policy. Minimise "
        "data collection to what is strictly necessary. Do not transmit PII without encryption."
    ),
    "call_log_contacts_internet_combo": (
        "Collect call logs only for clearly stated features. Disclose data collection in your privacy "
        "policy and comply with applicable regulations (GDPR, CCPA)."
    ),
    "location_contacts_internet_combo": (
        "Use coarse location instead of fine location where possible. Disclose to users when and why "
        "location data is transmitted. Provide opt-out mechanisms."
    ),
    "call_interception_combo": (
        "PROCESS_OUTGOING_CALLS is deprecated in API 29+. Migrate to TelecomManager or "
        "CallScreeningService APIs. Avoid logging or transmitting call metadata."
    ),
    "boot_install_internet_combo": (
        "Remove boot persistence unless genuinely required. Avoid silent installation of additional "
        "APKs. All downloads must be user-initiated and cryptographically verified."
    ),
    # Single permissions
    "install_packages_permission": (
        "Do not use INSTALL_PACKAGES unless your app is a legitimate package manager or app store. "
        "All installed packages should be verified against known-good signatures."
    ),
    "change_network_state": (
        "Ensure CHANGE_NETWORK_STATE is required for a declared feature. Avoid modifying network "
        "state in the background or in response to remote commands."
    ),
    "write_settings_permission": (
        "Minimise use of WRITE_SETTINGS. Require user confirmation before changing global settings. "
        "On Android 6+, this permission requires an explicit user action in Settings."
    ),
    "disable_keyguard_permission": (
        "Never disable the keyguard without explicit user intent (e.g. during a call). Remove this "
        "permission if not required for a documented feature."
    ),
    "biometric_permission": (
        "Use biometric authentication for access control only. Do not transmit biometric data remotely. "
        "Implement the BiometricPrompt API per Android documentation."
    ),
    # Manifest findings
    "device_admin_receiver": (
        "Remove device admin receivers unless building a legitimate MDM solution. Use Android Enterprise "
        "APIs and the Managed Profile framework instead. Provide clear user disclosure of admin capabilities."
    ),
    "device_admin_permission_declared": (
        "Avoid declaring BIND_DEVICE_ADMIN in the manifest unless building enterprise management software. "
        "Target Android Enterprise work profiles for B2B use cases."
    ),
    "accessibility_service_abuse": (
        "Accessibility services are restricted on Google Play for apps that do not directly assist users "
        "with disabilities. Remove the service or request an exemption through Play Console. "
        "Never use it to read screen content for non-accessibility purposes."
    ),
    "boot_persistence": (
        "Remove BOOT_COMPLETED listener unless your app genuinely needs to start at boot. "
        "Use WorkManager with periodic tasks instead for background work."
    ),
    "package_monitor": (
        "Remove PACKAGE_ADDED/REPLACED listeners unless building a package management feature. "
        "Avoid reacting to competitor app installations."
    ),
    "package_replace_monitor": (
        "Remove PACKAGE_REPLACED listener unless it serves a documented user-facing feature."
    ),
    "sms_receiver": (
        "Use the SMS Retriever API for one-time codes. Full RECEIVE_SMS access is restricted on "
        "Google Play to default SMS apps and selected enterprise use cases."
    ),
    "wap_push_receiver": (
        "Remove WAP_PUSH_RECEIVED listener unless your app is a carrier-grade messaging application. "
        "This permission is heavily restricted on Google Play."
    ),
    "send_intent_filter": (
        "Ensure the SEND intent filter is documented in your privacy policy and only used for "
        "legitimate sharing features."
    ),
    "backup_agent_misuse": (
        "Set android:allowBackup=\"false\" in the manifest unless backup is required. If backup is "
        "used, implement the BackupAgent interface carefully and avoid backing up sensitive data "
        "(keys, tokens, PII) in plaintext."
    ),
    "suspicious_activity_name": (
        "Rename activities to reflect their actual purpose. Remove overlay-style activities unless "
        "your app is a legitimate accessibility or launcher replacement."
    ),
    # Certificate findings
    "self_signed_cert": (
        "Self-signed certificates are acceptable for Android app signing. Ensure your keystore is "
        "securely stored and never committed to version control. Rotate keys if a compromise is suspected."
    ),
    "debug_certificate": (
        "Replace the debug signing certificate with a production release keystore before publishing. "
        "Never release debug-signed APKs to end users."
    ),
    "cert_validity_too_long": (
        "Consider shorter certificate validity periods with key rotation. "
        "Excessively long validity increases risk if the private key is compromised."
    ),
    "cert_validity_too_short": (
        "Increase the certificate validity period to avoid premature expiry. "
        "Android apps require the signing cert to be valid throughout the app lifecycle."
    ),
    "cert_expired": (
        "Re-sign the APK with a valid (non-expired) certificate. Expired signing certificates "
        "prevent app updates from being installed on user devices."
    ),
    # DEX / string findings
    "dynamic_code_loading": (
        "Avoid loading DEX/JAR files from external sources at runtime. If dynamic loading is required, "
        "verify all loaded code with cryptographic signatures before execution."
    ),
    "reflection_abuse": (
        "Limit use of Java reflection to well-defined, audited paths. Avoid invoking methods by "
        "string names that could be manipulated by external input."
    ),
    "root_detection_bypass": (
        "Implement root detection using multiple mechanisms (file checks, property checks, "
        "native code) and treat circumvention as a security event to report."
    ),
    "hardcoded_ip": (
        "Do not hardcode IP addresses or domain names in the app. Use configuration endpoints "
        "that can be updated without an app release."
    ),
    "hardcoded_secret": (
        "Remove secrets, API keys, and credentials from the APK binary. Store them server-side and "
        "fetch via authenticated API calls. Use Android Keystore for local key material."
    ),
    "insecure_http": (
        "Enforce HTTPS for all network communication. Set android:usesCleartextTraffic=\"false\" "
        "in the manifest and configure Network Security Config appropriately."
    ),
    "crypto_weak_algorithm": (
        "Replace weak cryptographic algorithms (MD5, SHA1, DES, ECB mode) with modern equivalents: "
        "SHA-256+, AES-GCM, or ChaCha20-Poly1305."
    ),
}

# High-risk permission risk assessment table
PERMISSION_RISK: dict[str, tuple[str, str]] = {
    "android.permission.SEND_SMS": ("High", "Can send paid SMS without user confirmation"),
    "android.permission.RECEIVE_SMS": ("High", "Can intercept incoming SMS including OTPs"),
    "android.permission.READ_SMS": ("High", "Can read all SMS messages on the device"),
    "android.permission.WRITE_SMS": ("Medium", "Can modify the SMS database"),
    "android.permission.CALL_PHONE": ("High", "Can make phone calls without user confirmation"),
    "android.permission.READ_CALL_LOG": ("High", "Can read full call history"),
    "android.permission.WRITE_CALL_LOG": ("Medium", "Can modify call history"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("High", "Can intercept and redirect outgoing calls"),
    "android.permission.RECORD_AUDIO": ("High", "Can record microphone audio"),
    "android.permission.CAMERA": ("High", "Can access device cameras"),
    "android.permission.ACCESS_FINE_LOCATION": ("High", "Can access precise GPS location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("Medium", "Can access approximate location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("High", "Can access location in the background"),
    "android.permission.READ_CONTACTS": ("High", "Can read all contacts"),
    "android.permission.WRITE_CONTACTS": ("Medium", "Can modify contacts"),
    "android.permission.GET_ACCOUNTS": ("Medium", "Can enumerate accounts configured on device"),
    "android.permission.BIND_DEVICE_ADMIN": ("Critical", "Can act as a device administrator"),
    "android.permission.INSTALL_PACKAGES": ("High", "Can silently install APK packages"),
    "android.permission.DELETE_PACKAGES": ("High", "Can silently uninstall apps"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("High", "Can request package installations"),
    "android.permission.REQUEST_DELETE_PACKAGES": ("Medium", "Can request package deletions"),
    "android.permission.DISABLE_KEYGUARD": ("High", "Can disable the screen lock"),
    "android.permission.WRITE_SETTINGS": ("Medium", "Can modify global system settings"),
    "android.permission.CHANGE_NETWORK_STATE": ("Low", "Can enable/disable network connectivity"),
    "android.permission.READ_EXTERNAL_STORAGE": ("Medium", "Can read files from external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Medium", "Can write files to external storage"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("High", "Broad access to all files on device"),
    "android.permission.USE_BIOMETRIC": ("Medium", "Can use biometric authentication APIs"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Medium", "Can start automatically at device boot"),
    "android.permission.INTERNET": ("Low", "Can access the internet"),
    "android.permission.WAKE_LOCK": ("Low", "Can prevent the CPU from sleeping"),
    "android.permission.FOREGROUND_SERVICE": ("Low", "Can run persistent foreground services"),
    "android.permission.USE_CREDENTIALS": ("Medium", "Can use authenticator account credentials"),
    "android.permission.AUTHENTICATE_ACCOUNTS": ("High", "Can act as an account authenticator"),
    "android.permission.MANAGE_ACCOUNTS": ("High", "Can manage accounts on device"),
}

# Color palette
_DARK_BG = colors.HexColor("#111827")
_HEADER_BG = colors.HexColor("#1e3a5f")
_ACCENT = colors.HexColor("#3b82f6")
_WHITE = colors.white
_LIGHT_GRAY = colors.HexColor("#f3f4f6")
_MID_GRAY = colors.HexColor("#6b7280")
_DARK_GRAY = colors.HexColor("#374151")

SEVERITY_BG = {
    "critical": colors.HexColor("#7f1d1d"),
    "high":     colors.HexColor("#7c2d12"),
    "medium":   colors.HexColor("#713f12"),
    "low":      colors.HexColor("#1f2937"),
}
SEVERITY_FG = {
    "critical": colors.HexColor("#fecaca"),
    "high":     colors.HexColor("#fed7aa"),
    "medium":   colors.HexColor("#fef08a"),
    "low":      colors.HexColor("#d1d5db"),
}
VERDICT_COLORS = {
    "pha":        colors.HexColor("#dc2626"),
    "suspicious": colors.HexColor("#d97706"),
    "clean":      colors.HexColor("#16a34a"),
    "unknown":    _MID_GRAY,
}
RISK_LEVEL_COLORS = {
    "Critical": colors.HexColor("#dc2626"),
    "High":     colors.HexColor("#ea580c"),
    "Medium":   colors.HexColor("#ca8a04"),
    "Low":      colors.HexColor("#6b7280"),
}


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

def generate_report(scan_data: dict, findings: list[dict]) -> bytes:
    """
    Generate a PDF security report and return raw bytes.

    Args:
        scan_data: dict with keys — filename, file_hash_sha256, verdict,
                   risk_score, pha_categories, created_at, completed_at,
                   metadata (dict: package_name, version, min_sdk, target_sdk,
                   permissions, sha256)
        findings:  list of dicts — category, severity, rule, description, evidence
    """
    buffer = BytesIO()
    filename = scan_data.get("filename", "Unknown")
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Security Report — {filename}",
        author="APK Malware Scanner",
    )

    styles = _build_styles()
    story: list = []

    story.extend(_executive_summary(scan_data, findings, styles))
    story.append(PageBreak())
    story.extend(_risk_breakdown(scan_data, findings, styles))
    story.append(PageBreak())
    story.extend(_findings_detail(findings, styles))

    metadata = scan_data.get("metadata") or {}
    permissions = metadata.get("permissions") or []
    if permissions:
        story.append(PageBreak())
        story.extend(_permissions_section(permissions, styles))

    cert_rules = {"self_signed_cert", "debug_certificate", "cert_expired",
                  "cert_validity_too_long", "cert_validity_too_short"}
    cert_findings = [f for f in findings
                     if f.get("rule") in cert_rules]
    story.append(PageBreak())
    story.extend(_certificate_section(cert_findings, metadata, styles))

    doc.build(story)
    return buffer.getvalue()


# ─────────────────────────────────────────────────────────────────
# Style helpers
# ─────────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    base = getSampleStyleSheet()

    def ps(name, **kwargs):
        return ParagraphStyle(name, parent=base["Normal"], **kwargs)

    return {
        "title":       ps("ReportTitle", fontSize=24, fontName="Helvetica-Bold",
                          textColor=_WHITE, alignment=TA_CENTER, spaceAfter=4),
        "subtitle":    ps("ReportSubtitle", fontSize=11, textColor=colors.HexColor("#93c5fd"),
                          alignment=TA_CENTER, spaceAfter=2),
        "section":     ps("SectionHead", fontSize=14, fontName="Helvetica-Bold",
                          textColor=_ACCENT, spaceBefore=12, spaceAfter=6),
        "body":        ps("Body", fontSize=9, textColor=_DARK_GRAY, leading=13),
        "body_white":  ps("BodyWhite", fontSize=9, textColor=_WHITE, leading=13),
        "mono":        ps("Mono", fontSize=8, fontName="Courier",
                          textColor=colors.HexColor("#a3e635"), leading=11),
        "label":       ps("Label", fontSize=8, fontName="Helvetica-Bold",
                          textColor=_MID_GRAY, spaceAfter=1),
        "value":       ps("Value", fontSize=9, textColor=_DARK_GRAY, spaceAfter=4),
        "finding_rule": ps("FindingRule", fontSize=9, fontName="Helvetica-Bold",
                           textColor=_DARK_GRAY),
        "remediation": ps("Remediation", fontSize=8, textColor=colors.HexColor("#166534"),
                          leading=12, leftIndent=8),
    }


def _hr(color=None):
    return HRFlowable(width="100%", thickness=0.5,
                      color=color or colors.HexColor("#e5e7eb"), spaceAfter=6)


def _section_title(text: str, styles: dict):
    return [Paragraph(text, styles["section"]), _hr()]


# ─────────────────────────────────────────────────────────────────
# Section builders
# ─────────────────────────────────────────────────────────────────

def _executive_summary(scan_data: dict, findings: list[dict], styles: dict) -> list:
    story = []
    metadata = scan_data.get("metadata") or {}
    verdict = scan_data.get("verdict", "unknown")
    risk_score = scan_data.get("risk_score") or 0
    pha_categories = scan_data.get("pha_categories") or []
    filename = scan_data.get("filename", "Unknown")
    package_name = metadata.get("package_name", "Unknown")
    version = metadata.get("version", "Unknown")
    created_at = _fmt_date(scan_data.get("created_at"))
    completed_at = _fmt_date(scan_data.get("completed_at"))

    # Cover banner
    banner_data = [[Paragraph(
        f'<font size="22"><b>Security Report</b></font>',
        styles["body_white"],
    )]]
    banner = Table(banner_data, colWidths=[BODY_W])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _HEADER_BG),
        ("TOPPADDING", (0, 0), (-1, -1), 20),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(banner)
    story.append(Spacer(1, 12))

    story.extend(_section_title("1. Executive Summary", styles))

    verdict_color = VERDICT_COLORS.get(verdict, _MID_GRAY)
    verdict_label = {"pha": "MALWARE", "suspicious": "SUSPICIOUS",
                     "clean": "CLEAN", "unknown": "UNKNOWN"}.get(verdict, verdict.upper())

    # Verdict + risk score side by side
    verdict_cell = Table(
        [[Paragraph(f"<b>Verdict</b>", styles["label"])],
         [Paragraph(f"<b>{verdict_label}</b>",
                    ParagraphStyle("v", parent=styles["body"],
                                   fontSize=18, textColor=verdict_color,
                                   fontName="Helvetica-Bold"))]],
        colWidths=[BODY_W * 0.5],
    )
    risk_color = (colors.HexColor("#dc2626") if risk_score >= 75 else
                  colors.HexColor("#d97706") if risk_score >= 40 else
                  colors.HexColor("#16a34a"))
    score_cell = Table(
        [[Paragraph("<b>Risk Score</b>", styles["label"])],
         [Paragraph(f"<b>{risk_score}/100</b>",
                    ParagraphStyle("rs", parent=styles["body"],
                                   fontSize=18, textColor=risk_color,
                                   fontName="Helvetica-Bold"))]],
        colWidths=[BODY_W * 0.5],
    )
    summary_row = Table([[verdict_cell, score_cell]], colWidths=[BODY_W * 0.5, BODY_W * 0.5])
    summary_row.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _LIGHT_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(summary_row)
    story.append(Spacer(1, 10))

    # App info table
    info_rows = [
        ["Filename", filename],
        ["Package Name", package_name],
        ["Version", version],
        ["Scan Date", created_at],
        ["Completed", completed_at or "—"],
        ["SHA-256", scan_data.get("file_hash_sha256") or metadata.get("sha256") or "—"],
        ["Total Findings", str(len(findings))],
        ["PHA Categories", ", ".join(pha_categories) if pha_categories else "None"],
    ]
    tbl = Table(
        [[Paragraph(f"<b>{k}</b>", styles["label"]),
          Paragraph(str(v), styles["body"])] for k, v in info_rows],
        colWidths=[BODY_W * 0.30, BODY_W * 0.70],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _LIGHT_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(tbl)

    # Severity summary
    if findings:
        story.append(Spacer(1, 10))
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.get("severity", "low")] = sev_counts.get(f.get("severity", "low"), 0) + 1

        sev_order = ["critical", "high", "medium", "low"]
        sev_row_data = [[
            Paragraph(f"<b>{sev.capitalize()}</b><br/>{sev_counts.get(sev, 0)}",
                      ParagraphStyle("sc", parent=styles["body"],
                                     textColor=SEVERITY_FG.get(sev, _WHITE),
                                     alignment=TA_CENTER, fontSize=10))
            for sev in sev_order
        ]]
        sev_tbl = Table(sev_row_data, colWidths=[BODY_W * 0.25] * 4)
        sev_tbl.setStyle(TableStyle([
            *[("BACKGROUND", (i, 0), (i, 0), SEVERITY_BG[sev])
              for i, sev in enumerate(sev_order)],
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#374151")),
        ]))
        story.append(sev_tbl)

    return story


def _risk_breakdown(scan_data: dict, findings: list[dict], styles: dict) -> list:
    story = []
    story.extend(_section_title("2. Risk Score Breakdown", styles))

    risk_score = scan_data.get("risk_score") or 0
    sev_weights = {"critical": 30, "high": 15, "medium": 8, "low": 3}

    # Bar chart — one row per severity
    severities = ["critical", "high", "medium", "low"]
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "low")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    chart_rows = []
    for sev in severities:
        count = sev_counts.get(sev, 0)
        contribution = min(count * sev_weights[sev], 100)
        bar_pct = min(int(contribution), 100)
        bar_col_width = BODY_W * 0.62
        bar_width = max(max(bar_pct, 2) / 100 * bar_col_width, 14)

        label_cell = Paragraph(f"<b>{sev.capitalize()}</b>  ×{count}",
                               ParagraphStyle("bl", parent=styles["body"],
                                              textColor=SEVERITY_FG.get(sev, _WHITE),
                                              fontSize=9))
        bar_inner = Table(
            [[Paragraph("", styles["body"])]],
            colWidths=[bar_width],
        )
        bar_inner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_BG[sev]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        pts_cell = Paragraph(f"<b>+{contribution} pts</b>",
                             ParagraphStyle("pts", parent=styles["body"],
                                            textColor=_MID_GRAY, fontSize=8,
                                            alignment=TA_LEFT))
        chart_rows.append([label_cell, bar_inner, pts_cell])

    chart = Table(chart_rows, colWidths=[BODY_W * 0.18, BODY_W * 0.62, BODY_W * 0.20])
    chart.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), _LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_LIGHT_GRAY, colors.white]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
    ]))
    story.append(chart)
    story.append(Spacer(1, 8))

    # Total risk score display
    total_row = Table(
        [[Paragraph(f"<b>Total Risk Score: {risk_score} / 100</b>",
                    ParagraphStyle("ts", parent=styles["body"],
                                   fontSize=13, textColor=_WHITE,
                                   fontName="Helvetica-Bold"))]],
        colWidths=[BODY_W],
    )
    total_color = (colors.HexColor("#991b1b") if risk_score >= 75 else
                   colors.HexColor("#92400e") if risk_score >= 40 else
                   colors.HexColor("#166534"))
    total_row.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), total_color),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#374151")),
    ]))
    story.append(total_row)

    # Category breakdown
    pha_categories = scan_data.get("pha_categories") or []
    if pha_categories:
        story.append(Spacer(1, 12))
        story.append(Paragraph("<b>Detected PHA Categories</b>", styles["label"]))
        cat_data = [[Paragraph(cat.replace("_", " ").title(), styles["body"])]
                    for cat in sorted(pha_categories)]
        cat_tbl = Table(cat_data, colWidths=[BODY_W])
        cat_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1),
             [colors.HexColor("#fef2f2"), colors.HexColor("#fff1f2")]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#fecaca")),
        ]))
        story.append(cat_tbl)

    return story


def _findings_detail(findings: list[dict], styles: dict) -> list:
    story = []
    story.extend(_section_title("3. Findings Detail", styles))

    if not findings:
        story.append(Paragraph("No findings detected. The app appears clean.", styles["body"]))
        return story

    sev_order = ["critical", "high", "medium", "low"]
    grouped: dict[str, list[dict]] = {s: [] for s in sev_order}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in grouped:
            grouped[sev].append(f)

    for sev in sev_order:
        group = grouped[sev]
        if not group:
            continue

        # Severity header row
        sev_header = Table(
            [[Paragraph(f"<b>{sev.upper()} — {len(group)} finding{'s' if len(group) != 1 else ''}</b>",
                        ParagraphStyle("sh", parent=styles["body"],
                                       textColor=SEVERITY_FG[sev],
                                       fontName="Helvetica-Bold", fontSize=10))]],
            colWidths=[BODY_W],
        )
        sev_header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_BG[sev]),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(KeepTogether([sev_header]))

        for idx, f in enumerate(group):
            rule = f.get("rule", "")
            category = f.get("category", "")
            description = f.get("description", "")
            evidence = f.get("evidence") or ""
            remediation = REMEDIATION.get(rule, "Review the finding and assess based on your app's requirements.")

            rows = [
                [Paragraph(f"<b>Rule</b>", styles["label"]),
                 Paragraph(rule, styles["finding_rule"])],
                [Paragraph("<b>Category</b>", styles["label"]),
                 Paragraph(category.replace("_", " ").title(), styles["body"])],
                [Paragraph("<b>Description</b>", styles["label"]),
                 Paragraph(description, styles["body"])],
            ]
            if evidence:
                rows.append([
                    Paragraph("<b>Evidence</b>", styles["label"]),
                    Paragraph(
                        f'<font name="Courier" size="8">{_escape(evidence)}</font>',
                        styles["body"],
                    ),
                ])
            rows.append([
                Paragraph("<b>Remediation</b>", styles["label"]),
                Paragraph(remediation, styles["body"]),
            ])

            finding_tbl = Table(rows, colWidths=[BODY_W * 0.22, BODY_W * 0.78])
            bg = colors.HexColor("#f9fafb") if idx % 2 == 0 else colors.white
            finding_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BACKGROUND", (0, -1), (0, -1), colors.HexColor("#f0fdf4")),
                ("BACKGROUND", (1, -1), (1, -1), colors.HexColor("#f0fdf4")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
            ]))
            story.append(finding_tbl)
            story.append(Spacer(1, 4))

        story.append(Spacer(1, 8))

    return story


def _permissions_section(permissions: list[str], styles: dict) -> list:
    story = []
    story.extend(_section_title("4. Permissions Analysis", styles))

    if not permissions:
        story.append(Paragraph("No permissions declared.", styles["body"]))
        return story

    header = [
        Paragraph("<b>Permission</b>", styles["label"]),
        Paragraph("<b>Risk</b>", styles["label"]),
        Paragraph("<b>Assessment</b>", styles["label"]),
    ]
    rows = [header]
    for perm in sorted(permissions):
        risk_level, assessment = PERMISSION_RISK.get(perm, ("Low", "Standard permission"))
        risk_color = RISK_LEVEL_COLORS.get(risk_level, _MID_GRAY)
        short_perm = perm.replace("android.permission.", "").replace(".", "_")
        rows.append([
            Paragraph(f'<font size="8" name="Courier">{short_perm}</font>', styles["body"]),
            Paragraph(f"<b>{risk_level}</b>",
                      ParagraphStyle("rl", parent=styles["body"],
                                     textColor=risk_color, fontSize=8,
                                     fontName="Helvetica-Bold")),
            Paragraph(assessment, styles["body"]),
        ])

    tbl = Table(rows, colWidths=[BODY_W * 0.42, BODY_W * 0.12, BODY_W * 0.46])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GRAY, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Total permissions declared: <b>{len(permissions)}</b>",
        styles["body"],
    ))
    return story


def _certificate_section(cert_findings: list[dict], metadata: dict, styles: dict) -> list:
    story = []
    story.extend(_section_title("5. Certificate Information", styles))

    if not cert_findings:
        story.append(Paragraph(
            "No certificate anomalies detected. The APK signing certificate appears valid.",
            styles["body"],
        ))
    else:
        story.append(Paragraph(
            f"<b>{len(cert_findings)}</b> certificate anomal{'y' if len(cert_findings) == 1 else 'ies'} detected:",
            styles["body"],
        ))
        story.append(Spacer(1, 6))
        for f in cert_findings:
            rule = f.get("rule", "")
            description = f.get("description", "")
            evidence = f.get("evidence") or ""
            severity = f.get("severity", "low")
            remediation = REMEDIATION.get(rule, "Review and remediate the certificate issue.")

            rows = [
                [Paragraph("<b>Anomaly</b>", styles["label"]),
                 Paragraph(rule.replace("_", " ").title(), styles["body"])],
                [Paragraph("<b>Severity</b>", styles["label"]),
                 Paragraph(severity.upper(),
                           ParagraphStyle("cs", parent=styles["body"],
                                          textColor=SEVERITY_FG.get(severity, _DARK_GRAY),
                                          fontName="Helvetica-Bold"))],
                [Paragraph("<b>Details</b>", styles["label"]),
                 Paragraph(description, styles["body"])],
            ]
            if evidence:
                rows.append([
                    Paragraph("<b>Evidence</b>", styles["label"]),
                    Paragraph(
                        f'<font name="Courier" size="8">{_escape(evidence)}</font>',
                        styles["body"],
                    ),
                ])
            rows.append([
                Paragraph("<b>Remediation</b>", styles["label"]),
                Paragraph(remediation, styles["body"]),
            ])

            cert_tbl = Table(rows, colWidths=[BODY_W * 0.22, BODY_W * 0.78])
            cert_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_BG.get(severity, _LIGHT_GRAY)),
                ("TEXTCOLOR", (0, 0), (-1, -1), SEVERITY_FG.get(severity, _DARK_GRAY)),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#374151")),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f0fdf4")),
                ("TEXTCOLOR", (0, -1), (-1, -1), colors.HexColor("#166534")),
            ]))
            story.append(cert_tbl)
            story.append(Spacer(1, 6))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Note: Android app signing certificates are self-signed by convention. "
        "The above findings flag anomalies relative to expected developer signing practices.",
        ParagraphStyle("note", parent=styles["body"], textColor=_MID_GRAY, fontSize=8),
    ))

    return story


# ─────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────

def _fmt_date(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso


def _escape(text: str) -> str:
    """Minimal XML escaping for ReportLab Paragraph content."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))
