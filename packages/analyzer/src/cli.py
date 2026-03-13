"""CLI entry point: python -m src.cli <apk_path> (or via apk-analyzer script)"""
import json
import sys

from .analyzer import analyze_apk


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.cli <apk_path>", file=sys.stderr)
        sys.exit(1)

    apk_path = sys.argv[1]
    try:
        result = analyze_apk(apk_path)
        print(json.dumps(result, indent=2))
    except FileNotFoundError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(json.dumps({"error": f"Analysis failed: {e}"}), file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
