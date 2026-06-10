"""Castellan command-line interface (Typer application)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from castellan.catalog import load_controls
from castellan.categorize import categorize as categorize_system
from castellan.fetch import DEFAULT_DATA_DIR, fetch_oscal_content
from castellan.models import (
    CheckResult,
    Control,
    Impact,
    SystemDescription,
    load_system_description,
)
from castellan.scanner.host import LinuxHost
from castellan.scanner.runner import run_all
from castellan.ssp import write_ssp

_OUTCOME_STYLES = {
    "pass": "[green]pass[/green]",
    "fail": "[red]fail[/red]",
    "error": "[yellow]error[/yellow]",
    "not_applicable": "[dim]n/a[/dim]",
}

app = typer.Typer(
    name="castellan",
    help="NIST 800-53 / RMF compliance toolkit: categorize, select, SSP, scan, report.",
    no_args_is_help=True,
)
ssp_app = typer.Typer(help="System Security Plan generation.", no_args_is_help=True)
app.add_typer(ssp_app, name="ssp")
console = Console()
err_console = Console(stderr=True)


@app.callback()
def main() -> None:
    """NIST 800-53 / RMF compliance toolkit: categorize, select, SSP, scan, report."""


def _load_controls_or_exit(baseline: Impact) -> list[Control]:
    """Load baseline controls, exiting non-zero if the OSCAL cache is missing."""
    try:
        return load_controls(baseline)
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None


def _load_system_or_exit(system_file: Path) -> SystemDescription:
    """Load a system description YAML file, exiting non-zero with a clear message on error."""
    try:
        return load_system_description(system_file)
    except FileNotFoundError:
        err_console.print(f"[red]Error:[/red] file not found: {system_file}")
        raise typer.Exit(code=1) from None
    except yaml.YAMLError as exc:
        err_console.print(f"[red]Error:[/red] invalid YAML in {system_file}: {exc}")
        raise typer.Exit(code=1) from None
    except (ValidationError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] invalid system description in {system_file}:\n{exc}")
        raise typer.Exit(code=1) from None


@app.command()
def categorize(
    system_file: Annotated[Path, typer.Argument(help="System description YAML file.")],
) -> None:
    """Print the FIPS-199 categorization and the selected 800-53B baseline."""
    system = _load_system_or_exit(system_file)
    result = categorize_system(system)

    table = Table(title=f"FIPS-199 Categorization — {system.name}")
    table.add_column("Security Objective")
    table.add_column("Impact Level")
    table.add_row("Confidentiality", result.confidentiality)
    table.add_row("Integrity", result.integrity)
    table.add_row("Availability", result.availability)
    console.print(table)
    console.print(f"Overall categorization (high-water mark): [bold]{result.overall}[/bold]")
    console.print(f"Selected SP 800-53B baseline: [bold]{result.selected_baseline}[/bold]")


@app.command()
def fetch(
    force: Annotated[
        bool, typer.Option("--force", help="Re-download files even if already cached.")
    ] = False,
) -> None:
    """Download and cache the NIST OSCAL catalog and baselines (one-time setup)."""
    try:
        downloaded = fetch_oscal_content(force=force)
    except Exception as exc:  # report any failure clearly, exit non-zero
        err_console.print(f"[red]Error:[/red] failed to fetch OSCAL content: {exc}")
        raise typer.Exit(code=1) from None
    if downloaded:
        for path in downloaded:
            console.print(f"downloaded [bold]{path.name}[/bold]")
    else:
        console.print(f"all OSCAL files already cached in {DEFAULT_DATA_DIR}")


@ssp_app.command("generate")
def ssp_generate(
    system_file: Annotated[Path, typer.Argument(help="System description YAML file.")],
    out_dir: Annotated[
        Path, typer.Option("--out", "-o", help="Directory to write ssp.md and ssp.json into.")
    ] = Path("out"),
) -> None:
    """Generate the System Security Plan: ssp.md (skeleton) and ssp.json (OSCAL)."""
    system = _load_system_or_exit(system_file)
    result = categorize_system(system)
    controls = _load_controls_or_exit(result.selected_baseline)

    md_path, json_path = write_ssp(system, result, controls, out_dir)
    console.print(
        f"Generated SSP for [bold]{system.name}[/bold] — "
        f"{result.selected_baseline} baseline, {len(controls)} controls"
    )
    console.print(f"  wrote {md_path}")
    console.print(f"  wrote {json_path}")


def _render_scan_table(results: list[CheckResult]) -> None:
    table = Table(title="Castellan host scan")
    table.add_column("Check")
    table.add_column("Title")
    table.add_column("Outcome")
    table.add_column("Detail", overflow="fold")
    for result in results:
        table.add_row(
            result.check_id,
            result.title,
            _OUTCOME_STYLES[result.outcome],
            result.detail,
        )
    console.print(table)
    counts = dict.fromkeys(_OUTCOME_STYLES, 0)
    for result in results:
        counts[result.outcome] += 1
    console.print(
        f"[green]{counts['pass']} pass[/green] · [red]{counts['fail']} fail[/red] · "
        f"[yellow]{counts['error']} error[/yellow] · "
        f"[dim]{counts['not_applicable']} not applicable[/dim]"
    )


@app.command()
def scan(
    out_dir: Annotated[
        Path | None,
        typer.Option("--out", help="Also write scan_results.json into this directory."),
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Print results as JSON instead of a table.")
    ] = False,
) -> None:
    """Run read-only hardening checks against the local Linux host."""
    if sys.platform != "linux":
        err_console.print(
            "[yellow]Warning:[/yellow] castellan scan inspects Linux host state; on "
            f"{sys.platform} most checks will be not_applicable."
        )
    results = run_all(LinuxHost())
    payload = json.dumps([result.model_dump() for result in results], indent=2)
    if as_json:
        typer.echo(payload)
    else:
        _render_scan_table(results)
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        results_path = out_dir / "scan_results.json"
        results_path.write_text(payload + "\n", encoding="utf-8", newline="\n")
        if not as_json:
            console.print(f"  wrote {results_path}")


if __name__ == "__main__":
    app()
