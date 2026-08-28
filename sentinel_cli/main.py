from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sentinel import __version__
from sentinel.db import get_case, init_db, list_cases, list_files, list_findings, session
from sentinel.pipeline import run_scan
from sentinel.reports.export import export_html, export_json
from sentinel.vault import crypto

app = typer.Typer(
    help="Sentinel — local DFIR workstation (scan, flags, reports, vault).",
    no_args_is_help=True,
)
vault_app = typer.Typer(help="Encrypted investigator vault.")
app.add_typer(vault_app, name="vault")
console = Console()


def _password_opt(password: Optional[str]) -> str:
    if password:
        return password
    return typer.prompt("Master password", hide_input=True)


@app.callback()
def _root() -> None:
    init_db()


@app.command()
def version() -> None:
    """Print Sentinel version."""
    console.print(f"sentinel {__version__}")


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, help="File or directory to scan"),
    case: str = typer.Option(..., "--case", "-c", help="Case name"),
    notes: Optional[str] = typer.Option(None, "--notes", "-n"),
) -> None:
    """Hash and inspect files, raise ATT&CK-mapped flags, store a case."""
    with console.status(f"Scanning {path} ..."):
        result = run_scan(path, case, notes=notes)
    console.print(
        f"[bold green]Case {result.id}[/] {result.name} — "
        f"{result.file_count} files, {result.finding_count} findings"
    )
    if result.id:
        _print_findings(result.id)


@app.command("cases")
def cases_cmd() -> None:
    """List investigation cases."""
    with session() as conn:
        rows = list_cases(conn)
    table = Table(title="Cases")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Files")
    table.add_column("Findings")
    table.add_column("Created")
    for row in rows:
        table.add_row(
            str(row.id),
            row.name,
            row.status,
            str(row.file_count),
            str(row.finding_count),
            row.created_at or "",
        )
    console.print(table)


@app.command()
def flags(
    case_id: int = typer.Argument(..., help="Case id"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s"),
) -> None:
    """List security flags for a case."""
    _print_findings(case_id, severity)


@app.command()
def files(
    case_id: int = typer.Argument(..., help="Case id"),
) -> None:
    """List scanned files for a case."""
    with session() as conn:
        if not get_case(conn, case_id):
            console.print(f"[red]Case {case_id} not found[/]")
            raise typer.Exit(1)
        rows = list_files(conn, case_id)
    table = Table(title=f"Files — case {case_id}")
    table.add_column("ID")
    table.add_column("Path")
    table.add_column("SHA-256")
    table.add_column("Entropy")
    table.add_column("Type")
    for row in rows:
        table.add_row(
            str(row["id"]),
            row["path"],
            (row["sha256"] or "")[:16] + "…",
            str(row["entropy"] or ""),
            f"{row['detected_type']} {row['extension']}",
        )
    console.print(table)


@app.command()
def report(
    case_id: int = typer.Argument(...),
    fmt: str = typer.Option("html", "--format", "-f", help="html or json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Export a forensic report."""
    dest = output or Path(f"sentinel-case-{case_id}.{fmt}")
    if fmt == "json":
        export_json(case_id, dest)
    elif fmt == "html":
        export_html(case_id, dest)
    else:
        console.print("[red]format must be html or json[/]")
        raise typer.Exit(1)
    console.print(f"Wrote [green]{dest}[/]")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Start the local FastAPI dashboard API (serves the UI if web/dist exists)."""
    import uvicorn

    console.print(f"Sentinel API on http://{host}:{port}")
    uvicorn.run("sentinel_api.main:app", host=host, port=port, reload=False)


def _print_findings(case_id: int, severity: str | None = None) -> None:
    with session() as conn:
        case = get_case(conn, case_id)
        if not case:
            console.print(f"[red]Case {case_id} not found[/]")
            raise typer.Exit(1)
        rows = list_findings(conn, case_id, severity)
    table = Table(title=f"Flags — {case.name}")
    table.add_column("Sev")
    table.add_column("Rule")
    table.add_column("ATT&CK")
    table.add_column("Title")
    table.add_column("File")
    colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
    for row in rows:
        sev = row["severity"]
        table.add_row(
            f"[{colors.get(sev, 'white')}]{sev}[/]",
            row["rule_id"],
            ", ".join(row["attack_ids"]),
            row["title"],
            row.get("file_path") or "",
        )
    if not rows:
        console.print("[dim]No findings.[/]")
        return
    console.print(table)


@vault_app.command("init")
def vault_init(
    password: Optional[str] = typer.Option(None, "--password", "-p"),
) -> None:
    """Create a new encrypted vault."""
    pw = _password_opt(password)
    confirm = typer.prompt("Confirm master password", hide_input=True)
    if pw != confirm:
        console.print("[red]Passwords do not match[/]")
        raise typer.Exit(1)
    crypto.init_vault(pw)
    console.print("[green]Vault created[/] (Argon2id + AES-256-GCM)")


@vault_app.command("list")
def vault_list(
    password: Optional[str] = typer.Option(None, "--password", "-p"),
    secrets: bool = typer.Option(False, "--secrets", help="Show secrets in plaintext"),
) -> None:
    """List vault entries."""
    payload = crypto.unlock(_password_opt(password))
    entries = crypto.list_entries(payload, include_secrets=secrets)
    table = Table(title="Vault")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Username")
    table.add_column("Secret")
    table.add_column("Updated")
    for entry in entries:
        table.add_row(
            entry.get("name", ""),
            entry.get("type", ""),
            entry.get("username", ""),
            entry.get("secret", ""),
            entry.get("updated_at", ""),
        )
    console.print(table)


@vault_app.command("add")
def vault_add(
    name: str = typer.Option(..., "--name"),
    entry_type: str = typer.Option("credential", "--type", help="credential | api_key | note"),
    username: str = typer.Option("", "--username", "-u"),
    secret: Optional[str] = typer.Option(None, "--secret", "-s"),
    notes: str = typer.Option("", "--notes"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
) -> None:
    """Add an entry to the vault."""
    pw = _password_opt(password)
    payload = crypto.unlock(pw)
    value = secret if secret is not None else typer.prompt("Secret", hide_input=True)
    crypto.add_entry(
        payload,
        name=name,
        entry_type=entry_type,
        username=username,
        secret=value,
        notes=notes,
    )
    crypto.save(pw, payload)
    console.print(f"[green]Stored[/] {name}")


@vault_app.command("generate")
def vault_generate(
    length: int = typer.Option(20, "--length", "-l"),
) -> None:
    """Generate a cryptographically random password (does not store it)."""
    console.print(crypto.generate_password(length))


@vault_app.command("backup")
def vault_backup(
    dest: Path = typer.Argument(...),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
) -> None:
    """Copy the encrypted vault file after verifying the master password."""
    crypto.export_backup(_password_opt(password), dest)
    console.print(f"Backup written to [green]{dest}[/]")


@vault_app.command("vt-key")
def vault_vt_key(
    api_key: Optional[str] = typer.Option(None, "--key"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
) -> None:
    """Store a VirusTotal API key in the vault as entry 'virustotal'."""
    pw = _password_opt(password)
    payload = crypto.unlock(pw)
    key = api_key or typer.prompt("VirusTotal API key", hide_input=True)
    existing = crypto.find_entry(payload, "virustotal")
    if existing:
        existing["secret"] = key
        existing["type"] = "api_key"
        crypto.save(pw, payload)
    else:
        crypto.add_entry(payload, name="virustotal", entry_type="api_key", secret=key)
        crypto.save(pw, payload)
    console.print("[green]VirusTotal key stored[/] (hash-only lookups)")


if __name__ == "__main__":
    app()
