"""APK / Mobile App malware scanner CLI.

Configuration (env vars or CLI flags):
  SCANNER_API_URL  — base URL of the scanner API  (default: http://localhost:3001)
  SCANNER_API_KEY  — API key sent as Bearer token  (optional)

Exit codes:
  0  — clean
  1  — suspicious
  2  — PHA / malware
  3  — error / unexpected
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

import click
import requests
from rich import box
from rich.console import Console
from rich.table import Table

console = Console()
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VERDICT_EXIT: dict[str, int] = {
    "clean": 0,
    "suspicious": 1,
    "pha": 2,
    "unknown": 3,
}

VERDICT_STYLE: dict[str, str] = {
    "clean": "green",
    "suspicious": "yellow",
    "pha": "bold red",
    "unknown": "dim",
}

SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}


def _build_session(api_key: str | None) -> requests.Session:
    s = requests.Session()
    if api_key:
        s.headers["Authorization"] = f"Bearer {api_key}"
    return s


def _api(ctx: click.Context) -> tuple[str, requests.Session]:
    """Return (base_url, session) from context."""
    return ctx.obj["url"], ctx.obj["session"]


def _fmt_json(data: Any) -> None:
    """Print JSON output."""
    import json
    click.echo(json.dumps(data, indent=2))


def _fmt_text_scan(scan: dict[str, Any]) -> None:
    verdict = scan.get("verdict", "unknown")
    style = VERDICT_STYLE.get(verdict, "")
    console.print(f"[bold]Scan ID:[/bold]  {scan['id']}")
    console.print(f"[bold]File:[/bold]     {scan.get('filename', '-')}")
    console.print(f"[bold]Status:[/bold]   {scan.get('status', '-')}")
    console.print(f"[bold]Verdict:[/bold]  [{style}]{verdict.upper()}[/{style}]")
    if scan.get("riskScore") is not None:
        console.print(f"[bold]Risk Score:[/bold] {scan['riskScore']}/100")
    if scan.get("phaCategories"):
        console.print(f"[bold]PHA Categories:[/bold] {', '.join(scan['phaCategories'])}")


def _fmt_table_scan(scan: dict[str, Any]) -> None:
    t = Table(box=box.SIMPLE)
    t.add_column("Field")
    t.add_column("Value")
    verdict = scan.get("verdict", "unknown")
    style = VERDICT_STYLE.get(verdict, "")
    rows = [
        ("Scan ID", scan["id"]),
        ("File", scan.get("filename", "-")),
        ("Status", scan.get("status", "-")),
        ("Verdict", f"[{style}]{verdict.upper()}[/{style}]"),
        ("Risk Score", str(scan["riskScore"]) + "/100" if scan.get("riskScore") is not None else "N/A"),
        ("PHA Categories", ", ".join(scan.get("phaCategories") or []) or "none"),
        ("Created", scan.get("createdAt", "-")),
        ("Completed", scan.get("completedAt") or "-"),
    ]
    for field, value in rows:
        t.add_row(field, value)
    console.print(t)


# ---------------------------------------------------------------------------
# Root CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.option(
    "--api-url",
    envvar="SCANNER_API_URL",
    default="http://localhost:3001",
    show_default=True,
    help="Base URL of the scanner API.",
)
@click.option(
    "--api-key",
    envvar="SCANNER_API_KEY",
    default=None,
    help="API key (Bearer token).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "table"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.pass_context
def cli(ctx: click.Context, api_url: str, api_key: str | None, fmt: str) -> None:
    """APK / Mobile App malware scanner CLI.

    \b
    Wraps the scanner REST API for use in CI/CD pipelines.
    Configure via env vars SCANNER_API_URL and SCANNER_API_KEY.
    """
    ctx.ensure_object(dict)
    ctx.obj["url"] = api_url.rstrip("/")
    ctx.obj["session"] = _build_session(api_key)
    ctx.obj["fmt"] = fmt


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--fail-above",
    default=60,
    show_default=True,
    type=float,
    help="Fail (exit 1 or 2) when risk score exceeds this threshold.",
)
@click.option("--poll-interval", default=3, show_default=True, type=int, help="Seconds between status polls.")
@click.option("--timeout", default=300, show_default=True, type=int, help="Max seconds to wait for scan completion.")
@click.pass_context
def scan(ctx: click.Context, file: str, fail_above: float, poll_interval: int, timeout: int) -> None:
    """Upload FILE and wait for the scan verdict.

    \b
    FILE can be an .apk, .ipa, or .zip.

    \b
    Exit codes:
      0 — clean (or risk score ≤ --fail-above)
      1 — suspicious (or risk score > --fail-above but < pha threshold)
      2 — PHA / malware
      3 — error
    """
    base_url, session = _api(ctx)
    fmt: str = ctx.obj["fmt"]
    file_path = Path(file)

    # Upload
    with console.status(f"Uploading [bold]{file_path.name}[/bold]…"):
        try:
            with open(file_path, "rb") as fh:
                resp = session.post(
                    f"{base_url}/api/scans",
                    files={"file": (file_path.name, fh)},
                    timeout=30,
                )
            resp.raise_for_status()
        except requests.RequestException as exc:
            err_console.print(f"[red]Upload failed:[/red] {exc}")
            sys.exit(3)

    data = resp.json()
    scan_id: str = data["id"]
    console.print(f"Scan queued → [cyan]{scan_id}[/cyan]")

    # Poll
    deadline = time.time() + timeout
    while True:
        if time.time() > deadline:
            err_console.print(f"[red]Timed out[/red] waiting for scan {scan_id}")
            sys.exit(3)
        time.sleep(poll_interval)
        try:
            resp = session.get(f"{base_url}/api/scans/{scan_id}", timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            err_console.print(f"[red]Poll error:[/red] {exc}")
            sys.exit(3)

        scan_data = resp.json()
        status = scan_data.get("status", "unknown")

        if status == "done":
            break
        if status == "error":
            msg = scan_data.get("errorMessage", "unknown error")
            err_console.print(f"[red]Scan failed:[/red] {msg}")
            sys.exit(3)

        console.print(f"  status: {status}…", end="\r")

    # Output
    if fmt == "json":
        _fmt_json(scan_data)
    elif fmt == "table":
        _fmt_table_scan(scan_data)
    else:
        _fmt_text_scan(scan_data)

    # Determine exit code
    verdict = scan_data.get("verdict", "unknown")
    risk_score = scan_data.get("riskScore")

    exit_code = VERDICT_EXIT.get(verdict, 3)

    # Override with threshold logic
    if risk_score is not None:
        if verdict == "clean" and risk_score > fail_above:
            exit_code = 1
        elif verdict == "suspicious" and risk_score <= fail_above:
            exit_code = 0

    sys.exit(exit_code)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("scan_id")
@click.pass_context
def status(ctx: click.Context, scan_id: str) -> None:
    """Check the status of a scan by SCAN_ID."""
    base_url, session = _api(ctx)
    fmt: str = ctx.obj["fmt"]

    try:
        resp = session.get(f"{base_url}/api/scans/{scan_id}", timeout=15)
        resp.raise_for_status()
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            err_console.print(f"[red]Scan not found:[/red] {scan_id}")
        else:
            err_console.print(f"[red]API error:[/red] {exc}")
        sys.exit(3)
    except requests.RequestException as exc:
        err_console.print(f"[red]Request failed:[/red] {exc}")
        sys.exit(3)

    scan_data = resp.json()

    if fmt == "json":
        _fmt_json(scan_data)
    elif fmt == "table":
        _fmt_table_scan(scan_data)
    else:
        _fmt_text_scan(scan_data)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--limit", default=20, show_default=True, type=int, help="Max results to display.")
@click.pass_context
def history(ctx: click.Context, limit: int) -> None:
    """List recent scans."""
    base_url, session = _api(ctx)
    fmt: str = ctx.obj["fmt"]

    try:
        resp = session.get(f"{base_url}/api/scans", timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        err_console.print(f"[red]Request failed:[/red] {exc}")
        sys.exit(3)

    scans: list[dict[str, Any]] = resp.json()
    # Most recent first
    scans = list(reversed(scans[-limit:]))

    if fmt == "json":
        _fmt_json(scans)
        return

    if not scans:
        console.print("No scans found.")
        return

    if fmt == "table":
        t = Table(title="Recent Scans", box=box.SIMPLE)
        t.add_column("ID", style="cyan")
        t.add_column("File")
        t.add_column("Status")
        t.add_column("Verdict")
        t.add_column("Risk")
        t.add_column("Created")
        for s in scans:
            verdict = s.get("verdict", "unknown")
            vstyle = VERDICT_STYLE.get(verdict, "")
            t.add_row(
                s["id"][:8] + "…",
                s.get("filename", "-"),
                s.get("status", "-"),
                f"[{vstyle}]{verdict.upper()}[/{vstyle}]",
                str(s["riskScore"]) if s.get("riskScore") is not None else "-",
                (s.get("createdAt") or "-")[:19],
            )
        console.print(t)
    else:
        for s in scans:
            verdict = s.get("verdict", "unknown")
            vstyle = VERDICT_STYLE.get(verdict, "")
            click.echo(
                f"{s['id'][:8]}…  {s.get('filename', '-'):40s}  "
                f"{s.get('status', '-'):10s}  {verdict.upper()}"
            )


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("scan_id")
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file path (default: scan-<id>.pdf in current directory).",
)
@click.pass_context
def report(ctx: click.Context, scan_id: str, output: str | None) -> None:
    """Download a PDF report for SCAN_ID."""
    base_url, session = _api(ctx)

    out_path = Path(output) if output else Path(f"scan-{scan_id}.pdf")

    with console.status(f"Downloading report for [cyan]{scan_id}[/cyan]…"):
        try:
            resp = session.get(f"{base_url}/api/scans/{scan_id}/report", timeout=60, stream=True)
            if resp.status_code == 409:
                data = resp.json()
                err_console.print(f"[yellow]Scan not complete yet:[/yellow] status={data.get('status')}")
                sys.exit(3)
            resp.raise_for_status()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                err_console.print(f"[red]Scan not found:[/red] {scan_id}")
            else:
                err_console.print(f"[red]API error:[/red] {exc}")
            sys.exit(3)
        except requests.RequestException as exc:
            err_console.print(f"[red]Request failed:[/red] {exc}")
            sys.exit(3)

        with open(out_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=8192):
                fh.write(chunk)

    console.print(f"[green]Report saved:[/green] {out_path}")
