"""
Flask HTTP service for the analyzer.
The Node backend calls POST /analyze with {"apk_path": "..."} and gets JSON back.
"""
import json
import os
from flask import Flask, request, jsonify

from .analyzer import analyze_apk

app = Flask(__name__)
PORT = int(os.environ.get("ANALYZER_PORT", 5001))

# Max request body size: 100 MB (matches the Node upload limit)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

# Allowed base directory for APK files — only files under this path are accepted
_UPLOADS_BASE = os.path.realpath(
    os.environ.get("UPLOADS_DIR", os.path.join(os.path.expanduser("~"), ".apk-scanner", "uploads"))
)


def _safe_apk_path(apk_path: str) -> str | None:
    """Resolve path and verify it stays within the allowed uploads directory."""
    resolved = os.path.realpath(os.path.abspath(apk_path))
    if not resolved.startswith(_UPLOADS_BASE + os.sep) and resolved != _UPLOADS_BASE:
        return None
    return resolved


@app.post("/analyze")
def analyze():
    data = request.get_json(force=True, silent=True) or {}
    apk_path = data.get("apk_path")
    if not apk_path:
        return jsonify({"error": "apk_path is required"}), 400

    safe_path = _safe_apk_path(apk_path)
    if safe_path is None:
        return jsonify({"error": "Invalid apk_path: path traversal detected"}), 400

    try:
        result = analyze_apk(safe_path)
        return jsonify(result)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


def main():
    app.run(host="0.0.0.0", port=PORT, debug=False)


if __name__ == "__main__":
    main()
