"""Castellan command-line interface (Typer application)."""

from __future__ import annotations

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
from castellan.models import Control, Impact, SystemDescription, load_system_description

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
) -> None:
    """Generate an SSP for the system (stub: lists the selected baseline controls)."""
    system = _load_system_or_exit(system_file)
    result = categorize_system(system)
    controls = _load_controls_or_exit(result.selected_baseline)

    table = Table(
        title=f"{system.name} — {result.selected_baseline} baseline ({len(controls)} controls)"
    )
    table.add_column("Control")
    table.add_column("Title")
    for control in controls:
        table.add_row(control.id, control.title)
    console.print(table)
    console.print("[dim]SSP rendering (ssp.md / ssp.json) arrives in Phase 3.[/dim]")


if __name__ == "__main__":
    app()
