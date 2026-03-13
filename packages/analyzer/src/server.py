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


@app.post("/analyze")
def analyze():
    data = request.get_json(force=True, silent=True) or {}
    apk_path = data.get("apk_path")
    if not apk_path:
        return jsonify({"error": "apk_path is required"}), 400

    try:
        result = analyze_apk(apk_path)
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
