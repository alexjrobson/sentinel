from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sentinel import __version__
from sentinel.db import (
    get_case,
    init_db,
    list_cases,
    list_files,
    list_findings,
    session,
    timeline_events,
    update_file_vt,
)
from sentinel.flags.engine import evaluate_record
from sentinel.intel.virustotal import VirusTotalError, lookup_virustotal, resolve_api_key
from sentinel.pipeline import run_scan
from sentinel.reports.export import export_html, export_json
from sentinel.vault import VaultError, VaultLocked, VaultSession, WrongPassword, generate_password

vault = VaultSession()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Sentinel", version=__version__, docs_url="/api/docs", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    path: str
    case: str
    notes: str | None = None


class VaultPassword(BaseModel):
    password: str


class VaultEntryIn(BaseModel):
    name: str
    type: str = "credential"
    username: str = ""
    secret: str = ""
    notes: str = ""


class GenerateRequest(BaseModel):
    length: int = Field(20, ge=8, le=128)


class VtLookupRequest(BaseModel):
    case_id: int
    file_id: int


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "version": __version__, "product": "Sentinel DFIR Workstation"}


@app.get("/api/cases")
def api_cases() -> list[dict[str, Any]]:
    with session() as conn:
        return [c.to_dict() for c in list_cases(conn)]


@app.get("/api/cases/{case_id}")
def api_case(case_id: int) -> dict[str, Any]:
    with session() as conn:
        case = get_case(conn, case_id)
        if not case:
            raise HTTPException(404, "Case not found")
        return {
            "case": case.to_dict(),
            "files": list_files(conn, case_id),
            "findings": list_findings(conn, case_id),
            "timeline": timeline_events(conn, case_id),
        }


@app.get("/api/cases/{case_id}/findings")
def api_findings(case_id: int, severity: str | None = Query(None)) -> list[dict[str, Any]]:
    with session() as conn:
        if not get_case(conn, case_id):
            raise HTTPException(404, "Case not found")
        return list_findings(conn, case_id, severity)


@app.post("/api/scan")
def api_scan(body: ScanRequest) -> dict[str, Any]:
    target = Path(body.path).expanduser()
    if not target.exists():
        raise HTTPException(400, f"Path not found: {target}")
    case = run_scan(target, body.case, notes=body.notes)
    return case.to_dict()


@app.get("/api/cases/{case_id}/report.json")
def api_report_json(case_id: int) -> JSONResponse:
    try:
        return JSONResponse(content=__import__("json").loads(export_json(case_id)))
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/cases/{case_id}/report.html")
def api_report_html(case_id: int) -> HTMLResponse:
    try:
        return HTMLResponse(export_html(case_id))
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/vault/status")
def vault_status() -> dict[str, Any]:
    return vault.status()


@app.post("/api/vault/init")
def vault_init(body: VaultPassword) -> dict[str, Any]:
    try:
        vault.init(body.password)
    except VaultError as exc:
        raise HTTPException(400, str(exc)) from exc
    return vault.status()


@app.post("/api/vault/unlock")
def vault_unlock(body: VaultPassword) -> dict[str, Any]:
    try:
        vault.unlock(body.password)
    except WrongPassword as exc:
        raise HTTPException(401, str(exc)) from exc
    except VaultError as exc:
        raise HTTPException(400, str(exc)) from exc
    return vault.status()


@app.post("/api/vault/lock")
def vault_lock() -> dict[str, Any]:
    vault.lock()
    return vault.status()


@app.get("/api/vault/entries")
def vault_entries(secrets: bool = False) -> list[dict[str, Any]]:
    try:
        return vault.entries(include_secrets=secrets)
    except VaultLocked as exc:
        raise HTTPException(401, str(exc)) from exc


@app.post("/api/vault/entries")
def vault_add(body: VaultEntryIn) -> dict[str, Any]:
    try:
        return vault.add(
            name=body.name,
            entry_type=body.type,
            username=body.username,
            secret=body.secret,
            notes=body.notes,
        )
    except VaultLocked as exc:
        raise HTTPException(401, str(exc)) from exc


@app.delete("/api/vault/entries/{entry_id}")
def vault_delete(entry_id: str) -> dict[str, bool]:
    try:
        ok = vault.delete(entry_id)
    except VaultLocked as exc:
        raise HTTPException(401, str(exc)) from exc
    if not ok:
        raise HTTPException(404, "Entry not found")
    return {"ok": True}


@app.post("/api/vault/generate")
def vault_generate(body: GenerateRequest) -> dict[str, str]:
    return {"password": generate_password(body.length)}


@app.get("/api/vault/backup")
def vault_backup() -> Response:
    from sentinel.config import vault_path

    path = vault_path()
    if not path.is_file():
        raise HTTPException(404, "Vault does not exist")
    if not vault.unlocked:
        raise HTTPException(401, "Unlock the vault before exporting a backup")
    return Response(
        content=path.read_bytes(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=sentinel-vault.bin"},
    )


@app.post("/api/intel/vt-lookup")
def vt_lookup(body: VtLookupRequest) -> dict[str, Any]:
    with session() as conn:
        case = get_case(conn, body.case_id)
        if not case:
            raise HTTPException(404, "Case not found")
        files = {f["id"]: f for f in list_files(conn, body.case_id)}
        record = files.get(body.file_id)
        if not record:
            raise HTTPException(404, "File not found in case")
        sha256 = record.get("sha256")
        if not sha256:
            raise HTTPException(400, "File has no SHA-256")

        vt_key = None
        if vault.unlocked:
            vt_key = vault.secret_named("virustotal")
        api_key = resolve_api_key(vt_key)
        if not api_key:
            raise HTTPException(
                400,
                "No VirusTotal API key. Store one in the vault as 'virustotal' or set VIRUSTOTAL_API_KEY.",
            )
        try:
            result = lookup_virustotal(sha256, api_key)
        except VirusTotalError as exc:
            raise HTTPException(502, str(exc)) from exc

        update_file_vt(conn, body.file_id, result)
        # Re-flag if VT says malicious and we don't already have that finding.
        from sentinel.models import FileRecord

        fr = FileRecord(
            path=record["path"],
            size=record["size"] or 0,
            md5=record.get("md5") or "",
            sha1=record.get("sha1") or "",
            sha256=sha256,
            detected_type=record.get("detected_type") or "",
            extension=record.get("extension") or "",
            magic_mismatch=bool(record.get("magic_mismatch")),
            entropy=record.get("entropy"),
            iocs=record.get("iocs") or {},
            yara_hits=record.get("yara_hits") or [],
            vt=result,
        )
        new_findings = [f for f in evaluate_record(fr) if f.rule_id == "vt_malicious"]
        from sentinel.db import insert_finding

        for finding in new_findings:
            finding.file_id = body.file_id
            insert_finding(conn, body.case_id, finding)

        return result


WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"
if WEB_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB_DIST), html=True), name="ui")
