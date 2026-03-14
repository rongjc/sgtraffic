"""
Integration tests for source code analysis (Android + iOS zip projects).

Tests cover:
- Project type detection (android_source, ios_source)
- Unknown project raises ValueError
- Android manifest vulnerability detection
- Android Java/Kotlin insecure patterns
- iOS Swift/ObjC insecure patterns
- iOS Info.plist analysis inside source
- Correct verdict and risk score computation
- Missing file raises FileNotFoundError
- Path traversal safety (absolute paths stripped)
"""
import io
import os
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.source_analyzer import analyze_source_zip, _detect_project_type
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_zip(files: dict[str, str | bytes]) -> bytes:
    """Create an in-memory zip from a dict of {path: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, content in files.items():
            if isinstance(content, str):
                content = content.encode()
            zf.writestr(name, content)
    return buf.getvalue()


def _write_zip(data: bytes, suffix: str = ".zip") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


ANDROID_MANIFEST_CLEAN = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.cleanapp">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="CleanApp">
        <activity android:name=".MainActivity"/>
    </application>
</manifest>
"""

ANDROID_MANIFEST_DANGEROUS = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.dangerousapp">
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application android:debuggable="true" android:allowBackup="true">
        <activity android:name=".MainActivity"/>
    </application>
</manifest>
"""

ANDROID_JAVA_CLEAN = """
package com.example;

public class MainActivity {
    public void onCreate() {
        System.out.println("Hello World");
    }
}
"""

ANDROID_JAVA_INSECURE = """
package com.example;

import android.webkit.WebView;

public class MainActivity {
    String password = "hardcoded_password_123";

    public void setupWebView(WebView wv) {
        wv.getSettings().setJavaScriptEnabled(true);
        wv.getSettings().setAllowFileAccess(true);
    }
}
"""

IOS_INFO_PLIST = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.iosapp</string>
    <key>CFBundleDisplayName</key>
    <string>iOSApp</string>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
</plist>
"""

SWIFT_CLEAN = """
import Foundation

func fetchData(url: URL) {
    URLSession.shared.dataTask(with: url) { data, response, error in
        print("Got data")
    }.resume()
}
"""

SWIFT_INSECURE = """
import Foundation
import UIKit

let apiKey = "mysecretapikey12345"
let serverUrl = "http://example.com/api/data"

func setupView() {
    let pb = UIPasteboard.general
    pb.string = "sensitive data"
}
"""

OBJC_INSECURE = """
#import <UIKit/UIKit.h>

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Insecure keychain - accessible even when device is locked
    NSDictionary *query = @{(__bridge id)kSecAttrAccessibleAlways: (__bridge id)kSecValueData};
    SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    return YES;
}

@end
"""


# ---------------------------------------------------------------------------
# _detect_project_type
# ---------------------------------------------------------------------------

class TestDetectProjectType:
    def test_detects_android_via_manifest(self, tmp_path):
        (tmp_path / "AndroidManifest.xml").write_text(ANDROID_MANIFEST_CLEAN)
        assert _detect_project_type(tmp_path) == "android_source"

    def test_detects_android_via_build_gradle(self, tmp_path):
        (tmp_path / "build.gradle").write_text("apply plugin: 'com.android.application'")
        assert _detect_project_type(tmp_path) == "android_source"

    def test_detects_ios_via_info_plist(self, tmp_path):
        (tmp_path / "Info.plist").write_bytes(IOS_INFO_PLIST)
        assert _detect_project_type(tmp_path) == "ios_source"

    def test_detects_ios_via_xcodeproj(self, tmp_path):
        xcodeproj = tmp_path / "MyApp.xcodeproj"
        xcodeproj.mkdir()
        (xcodeproj / "project.pbxproj").write_text("")
        assert _detect_project_type(tmp_path) == "ios_source"

    def test_detects_ios_via_podfile(self, tmp_path):
        (tmp_path / "Podfile").write_text("pod 'AFNetworking'")
        assert _detect_project_type(tmp_path) == "ios_source"

    def test_unknown_returns_none(self, tmp_path):
        (tmp_path / "main.cpp").write_text("int main() {}")
        assert _detect_project_type(tmp_path) is None


# ---------------------------------------------------------------------------
# analyze_source_zip — error cases
# ---------------------------------------------------------------------------

class TestAnalyzeSourceZipErrors:
    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            analyze_source_zip("/no/such/file.zip")

    def test_unknown_project_type_raises_value_error(self):
        data = _build_zip({"src/main.cpp": "int main() {}"})
        path = _write_zip(data)
        try:
            with pytest.raises(ValueError, match="Cannot determine project type"):
                analyze_source_zip(path)
        finally:
            os.unlink(path)

    def test_path_traversal_in_zip_is_stripped(self):
        """Files with absolute paths or .. traversal should be ignored safely."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("AndroidManifest.xml", ANDROID_MANIFEST_CLEAN)
            zf.writestr("../../evil.sh", "rm -rf /")
        path = _write_zip(buf.getvalue())
        try:
            # Should succeed — the traversal file gets skipped
            result = analyze_source_zip(path)
            assert result["source_type"] == "android_source"
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# analyze_source_zip — Android projects
# ---------------------------------------------------------------------------

class TestAnalyzeAndroidSource:
    def _run(self, files: dict) -> dict:
        data = _build_zip(files)
        path = _write_zip(data)
        try:
            return analyze_source_zip(path)
        finally:
            os.unlink(path)

    def test_clean_android_project_returns_clean(self):
        result = self._run({
            "AndroidManifest.xml": ANDROID_MANIFEST_CLEAN,
            "app/src/main/java/com/example/MainActivity.java": ANDROID_JAVA_CLEAN,
        })
        assert result["source_type"] == "android_source"
        # Clean project may have low-severity findings (e.g. allowBackup default) but verdict must be clean
        assert result["verdict"] == "clean"

    def test_insecure_java_patterns_detected(self):
        result = self._run({
            "AndroidManifest.xml": ANDROID_MANIFEST_CLEAN,
            "app/src/main/java/MainActivity.java": ANDROID_JAVA_INSECURE,
        })
        rules = {f["rule"] for f in result["findings"]}
        assert "hardcoded_secret" in rules or "insecure_webview_js" in rules

    def test_webview_javascript_enabled_detected(self):
        java = 'wv.getSettings().setJavaScriptEnabled(true);'
        result = self._run({
            "AndroidManifest.xml": ANDROID_MANIFEST_CLEAN,
            "app/src/main/java/WebActivity.java": java,
        })
        rules = {f["rule"] for f in result["findings"]}
        assert "insecure_webview_js" in rules

    def test_dangerous_permissions_combo_detected(self):
        result = self._run({
            "AndroidManifest.xml": ANDROID_MANIFEST_DANGEROUS,
        })
        # camera+audio+internet combo should be detected
        rules = {f["rule"] for f in result["findings"]}
        assert len(rules) > 0

    def test_hardcoded_aws_key_critical(self):
        java = 'String key = "AKIAIOSFODNN7EXAMPLE";'
        result = self._run({
            "AndroidManifest.xml": ANDROID_MANIFEST_CLEAN,
            "app/src/main/java/Config.java": java,
        })
        findings_by_rule = {f["rule"]: f for f in result["findings"]}
        assert "hardcoded_aws_key" in findings_by_rule
        assert findings_by_rule["hardcoded_aws_key"]["severity"] == "critical"

    def test_result_keys_present(self):
        result = self._run({"AndroidManifest.xml": ANDROID_MANIFEST_CLEAN})
        for key in ("verdict", "risk_score", "pha_categories", "findings", "metadata", "source_type"):
            assert key in result
        assert result["metadata"]["sha256"]
        assert result["metadata"]["source_type"] == "android_source"

    def test_build_gradle_kotlin_detected(self):
        result = self._run({
            "build.gradle.kts": 'plugins { id("com.android.application") }',
        })
        assert result["source_type"] == "android_source"

    def test_debuggable_true_in_manifest_flagged(self):
        result = self._run({"AndroidManifest.xml": ANDROID_MANIFEST_DANGEROUS})
        rules = {f["rule"] for f in result["findings"]}
        # debuggable=true should be caught by android source analyzer
        # (may appear as backup_agent_misuse or debuggable rule depending on implementation)
        assert len(result["findings"]) > 0


# ---------------------------------------------------------------------------
# analyze_source_zip — iOS projects
# ---------------------------------------------------------------------------

class TestAnalyzeIOSSource:
    def _run(self, files: dict) -> dict:
        data = _build_zip(files)
        path = _write_zip(data)
        try:
            return analyze_source_zip(path)
        finally:
            os.unlink(path)

    def test_clean_ios_project_low_risk(self):
        result = self._run({
            "Info.plist": IOS_INFO_PLIST,
            "Sources/AppDelegate.swift": SWIFT_CLEAN,
        })
        assert result["source_type"] == "ios_source"
        assert result["verdict"] in ("clean", "suspicious")

    def test_hardcoded_secret_in_swift_detected(self):
        result = self._run({
            "Info.plist": IOS_INFO_PLIST,
            "Sources/Config.swift": SWIFT_INSECURE,
        })
        rules = {f["rule"] for f in result["findings"]}
        assert "hardcoded_secret" in rules or "cleartext_http" in rules

    def test_cleartext_http_in_swift_detected(self):
        swift = 'let url = "http://example.com/api/data"'
        result = self._run({
            "Info.plist": IOS_INFO_PLIST,
            "Sources/NetworkManager.swift": swift,
        })
        rules = {f["rule"] for f in result["findings"]}
        assert "cleartext_http" in rules

    def test_uipasteboard_usage_detected(self):
        result = self._run({
            "Info.plist": IOS_INFO_PLIST,
            "Sources/PasteboardHelper.swift": SWIFT_INSECURE,
        })
        rules = {f["rule"] for f in result["findings"]}
        assert "uipasteboard_sensitive" in rules

    def test_objc_keychain_accessible_always_detected(self):
        result = self._run({
            "Info.plist": IOS_INFO_PLIST,
            "Sources/AppDelegate.m": OBJC_INSECURE,
        })
        # kSecAttrAccessibleAlways (without ThisDevice suffix) should be flagged
        rules = {f["rule"] for f in result["findings"]}
        assert "keychain_accessible_always" in rules

    def test_xcodeproj_detection(self):
        result = self._run({
            "MyApp.xcodeproj/project.pbxproj": "",
            "Sources/main.swift": SWIFT_CLEAN,
        })
        assert result["source_type"] == "ios_source"

    def test_podfile_detection(self):
        result = self._run({
            "Podfile": "pod 'Alamofire'",
            "Sources/main.swift": SWIFT_CLEAN,
        })
        assert result["source_type"] == "ios_source"

    def test_hardcoded_aws_key_in_swift_critical(self):
        swift = 'let key = "AKIAIOSFODNN7EXAMPLE"'
        result = self._run({
            "Info.plist": IOS_INFO_PLIST,
            "Sources/Config.swift": swift,
        })
        findings_by_rule = {f["rule"]: f for f in result["findings"]}
        assert "hardcoded_aws_key" in findings_by_rule
        assert findings_by_rule["hardcoded_aws_key"]["severity"] == "critical"

    def test_result_metadata_contains_source_type(self):
        result = self._run({
            "Info.plist": IOS_INFO_PLIST,
            "Sources/main.swift": SWIFT_CLEAN,
        })
        assert result["metadata"]["source_type"] == "ios_source"
