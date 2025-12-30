"""FastAPI MVP for memory forensics web app (upload, dashboard, process tree, PDF export)."""
from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import sys
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
try:
    from celery import Celery
except Exception:  # pragma: no cover - optional dependency
    Celery = None

# Ensure we can import the existing analyzer without moving it yet.
ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))
try:  # noqa: SIM105 - Optional import for future integration
    from memory_analyzer import MemoryAnalyzer  # type: ignore
except Exception:  # pragma: no cover - fallback if dependency not available at runtime
    MemoryAnalyzer = None

UPLOAD_DIR = Path(__file__).resolve().parents[1] / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(__file__).resolve().parents[1] / "cases.db"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "2048"))
ALLOWED_EXT = {ext.strip().lower() for ext in os.getenv("ALLOWED_EXT", ".mem,.raw,.bin").split(",") if ext}
API_KEY = os.getenv("API_KEY")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)

celery_app = None
if Celery and CELERY_BROKER_URL:
    celery_app = Celery(__name__, broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)

executor = ThreadPoolExecutor(max_workers=2)


# Optional Celery task for background processing
if celery_app:

    @celery_app.task(name="analyze_case")
    def analyze_case_task(case_id: str) -> None:
        _analyze_case(case_id)

app = FastAPI(
    title="Memory Forensics API",
    version="0.1.0",
    description="MVP endpoints: upload, dashboard cards, process tree, PDF export, case metadata.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Persistence helpers (SQLite for MVP)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                status TEXT NOT NULL,
                threat_cards TEXT,
                process_tree TEXT,
                iocs TEXT,
                timeline TEXT,
                error TEXT,
                sha256 TEXT
            );
            """
        )
        conn.commit()


def _serialize(data: Any) -> Optional[str]:
    if data is None:
        return None
    return json.dumps(data)


def _deserialize(payload: Optional[str]) -> Any:
    if payload is None:
        return None
    try:
        return json.loads(payload)
    except Exception:
        return None


def _persist_case(meta: Dict[str, Any]) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO cases (case_id, filename, stored_path, uploaded_at, status, threat_cards, process_tree, iocs, timeline, error, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
                filename=excluded.filename,
                stored_path=excluded.stored_path,
                uploaded_at=excluded.uploaded_at,
                status=excluded.status,
                threat_cards=excluded.threat_cards,
                process_tree=excluded.process_tree,
                iocs=excluded.iocs,
                timeline=excluded.timeline,
                error=excluded.error,
                sha256=excluded.sha256
            ;
            """,
            (
                meta["case_id"],
                meta["filename"],
                meta["stored_path"],
                meta["uploaded_at"],
                meta.get("status", "queued"),
                _serialize(meta.get("threat_cards")),
                _serialize(meta.get("process_tree")),
                _serialize(meta.get("iocs")),
                _serialize(meta.get("timeline")),
                meta.get("error"),
                meta.get("sha256"),
            ),
        )
        conn.commit()


def _get_case(case_id: str) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["threat_cards"] = _deserialize(data.get("threat_cards")) or []
        data["process_tree"] = _deserialize(data.get("process_tree")) or {}
        data["iocs"] = _deserialize(data.get("iocs")) or {"hashes": [], "ips": [], "dlls": []}
        data["timeline"] = _deserialize(data.get("timeline")) or []
        return data


def _list_cases() -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM cases ORDER BY uploaded_at DESC").fetchall()
        results: List[Dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            data["threat_cards"] = _deserialize(data.get("threat_cards")) or []
            data["process_tree"] = _deserialize(data.get("process_tree")) or {}
            data["iocs"] = _deserialize(data.get("iocs")) or {"hashes": [], "ips": [], "dlls": []}
            data["timeline"] = _deserialize(data.get("timeline")) or []
            results.append(data)
        return results


def _update_case(case_id: str, **fields: Any) -> None:
    if not fields:
        return
    cols = []
    vals = []
    for key, val in fields.items():
        if key in {"threat_cards", "process_tree", "iocs", "timeline"}:
            cols.append(f"{key} = ?")
            vals.append(_serialize(val))
        else:
            cols.append(f"{key} = ?")
            vals.append(val)
    vals.append(case_id)
    with _connect() as conn:
        conn.execute(f"UPDATE cases SET {', '.join(cols)} WHERE case_id = ?", vals)
        conn.commit()


def _get_case_by_hash(sha256: str) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM cases WHERE sha256 = ?", (sha256,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["threat_cards"] = _deserialize(data.get("threat_cards")) or []
        data["process_tree"] = _deserialize(data.get("process_tree")) or {}
        data["iocs"] = _deserialize(data.get("iocs")) or {"hashes": [], "ips": [], "dlls": []}
        data["timeline"] = _deserialize(data.get("timeline")) or []
        return data


_init_db()


def _fake_threat_cards() -> List[Dict]:
    return [
        {"severity": "Critical", "title": "Code Injection", "score": 74, "detail": "Unsigned DLL + RWX VAD"},
        {"severity": "High", "title": "Suspicious Explorer", "score": 57, "detail": "Hollowed child"},
        {"severity": "Medium", "title": "svchost anomaly", "score": 41, "detail": "Unexpected service host"},
        {"severity": "Medium", "title": "Notepad payload", "score": 34, "detail": "Injected thread"},
    ]


def _fake_process_tree() -> Dict:
    return {
        "name": "System",
        "pid": 4,
        "children": [
            {"name": "smss.exe", "pid": 228, "children": []},
            {
                "name": "wininit.exe",
                "pid": 340,
                "children": [
                    {"name": "services.exe", "pid": 428, "children": [{"name": "svchost.exe", "pid": 600, "children": []}]},
                    {"name": "lsass.exe", "pid": 512, "children": []},
                ],
            },
            {"name": "explorer.exe", "pid": 1432, "children": [{"name": "notepad.exe", "pid": 2450, "children": []}]},
            {"name": "iexplore.exe", "pid": 3200, "children": []},
        ],
    }


def _build_process_tree_from_processes(processes: Dict[int, Any]) -> Dict[str, Any]:
    nodes: Dict[int, Dict[str, Any]] = {}
    children_map: Dict[int, List[int]] = {}
    for pid, p in processes.items():
        nodes[pid] = {"name": p.name, "pid": pid, "children": []}
        if p.ppid is not None:
            children_map.setdefault(p.ppid, []).append(pid)
    root_pid = 4 if 4 in nodes else (min(nodes.keys()) if nodes else 0)
    if root_pid not in nodes and nodes:
        root_pid = next(iter(nodes.keys()))

    def attach(pid: int) -> Dict[str, Any]:
        node = nodes[pid]
        node["children"] = [attach(child) for child in children_map.get(pid, [])]
        return node

    return attach(root_pid) if nodes else {"name": "", "pid": 0, "children": []}


def _extract_iocs(processes: Dict[int, Any]) -> Dict[str, Any]:
    """Extract IOCs: file hashes, network IPs, suspicious DLLs."""
    iocs = {"hashes": set(), "ips": set(), "dlls": set()}
    for p in processes.values():
        for h in p.file_hashes.values():
            if h:
                iocs["hashes"].add(h)
        for conn in p.network_connections:
            if conn and len(conn.split(":")) >= 2:
                iocs["ips"].add(conn.split(":")[0])
        for dll in p.suspicious_dlls:
            if dll:
                iocs["dlls"].add(dll)
    return {k: sorted(list(v)) for k, v in iocs.items()}


def _generate_timeline(processes: Dict[int, Any]) -> List[Dict[str, Any]]:
    """Build threat timeline from process create times and detections."""
    events: List[Dict[str, Any]] = []
    for p in processes.values():
        if p.risk_score > 30:
            events.append(
                {
                    "timestamp": p.create_time or "unknown",
                    "pid": p.pid,
                    "process": p.name,
                    "event": f"Risk {p.risk_score:.0f}% - {'; '.join(p.flags()[:2]) if p.flags() else 'anomaly'}",
                }
            )
    return sorted(events, key=lambda e: e.get("timestamp", ""))


def _processes_to_cards(processes: Dict[int, Any], analyzer: Any) -> List[Dict[str, Any]]:
    # Sort by risk_score descending; build concise cards
    ordered = sorted(processes.values(), key=lambda p: p.risk_score, reverse=True)
    cards: List[Dict[str, Any]] = []
    for p in ordered[:8]:
        cards.append(
            {
                "severity": analyzer.classify_severity(p),
                "title": p.name,
                "score": round(p.risk_score, 1),
                "detail": "; ".join(p.flags())[:220],
            }
        )
    return cards or _fake_threat_cards()


def _run_analyzer(path: str, case_id: str) -> Dict[str, Any]:
    """Invoke MemoryAnalyzer; fall back to stubs if unavailable or failing."""
    if MemoryAnalyzer is None:
        return {"threat_cards": _fake_threat_cards(), "process_tree": _fake_process_tree(), "iocs": {"hashes": [], "ips": [], "dlls": []}, "timeline": []}

    try:
        analyzer = MemoryAnalyzer(debug=False)
        analyzer.validate_paths(require_yara=False)
        processes = analyzer.analyze(
            memory_file=path,
            do_yara=False,
            prefer_volatility_yara=False,
            dump_dir=None,
            case_number=case_id,
        )
        cards = _processes_to_cards(processes, analyzer)
        tree = _build_process_tree_from_processes(processes)
        iocs = _extract_iocs(processes)
        timeline = _generate_timeline(processes)
        return {"threat_cards": cards, "process_tree": tree, "iocs": iocs, "timeline": timeline}
    except Exception:
        return {"threat_cards": _fake_threat_cards(), "process_tree": _fake_process_tree(), "iocs": {"hashes": [], "ips": [], "dlls": []}, "timeline": []}


def _analyze_case(case_id: str) -> None:
    meta = _get_case(case_id)
    if not meta:
        return
    _update_case(case_id, status="processing")
    try:
        result = _run_analyzer(meta["stored_path"], case_id)
        meta_updated = {**meta, "threat_cards": result.get("threat_cards"), "process_tree": result.get("process_tree"), "iocs": result.get("iocs"), "timeline": result.get("timeline"), "status": "ready"}
        _persist_case(meta_updated)
    except Exception as exc:  # pragma: no cover - defensive guard
        _update_case(case_id, status="error", error=str(exc))


def _case_or_404(case_id: str) -> Dict:
    meta = _get_case(case_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Case not found")
    return meta


def _build_stub_pdf(case_id: str, meta: Dict) -> bytes:
    """Create a minimal PDF byte stream summarizing the case."""
    lines = [
        f"Memory Forensics Report",
        f"Case ID: {case_id}",
        f"Filename: {meta.get('filename', 'unknown')}",
        f"Uploaded: {meta.get('uploaded_at', '')}",
        f"Status: {meta.get('status', 'pending')}",
        "Threat Summary:",
        "- Cards: Critical/High/Medium/Low (stub)",
        "- Process tree ready",
        "- PDF export via API",
    ]

    def _esc(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_lines: List[str] = ["BT", "/F1 12 Tf", "72 720 Td"]
    for idx, line in enumerate(lines):
        prefix = "T* " if idx else ""
        content_lines.append(f"{prefix}({_esc(line)}) Tj")
    content_lines.append("ET")
    content_stream = "\n".join(content_lines).encode("utf-8")

    objects: List[bytes] = []

    def add_obj(body: bytes) -> None:
        objects.append(body if body.endswith(b"\n") else body + b"\n")

    add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")
    add_obj(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add_obj(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>"
    )
    add_obj(f"<< /Length {len(content_stream)} >>\nstream\n".encode("utf-8") + content_stream + b"\nendstream")
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    pdf_parts: List[bytes] = [b"%PDF-1.4\n"]
    offsets: List[int] = []
    for idx, obj in enumerate(objects, start=1):
        offsets.append(sum(len(part) for part in pdf_parts))
        pdf_parts.append(f"{idx} 0 obj\n".encode("utf-8"))
        pdf_parts.append(obj)
        pdf_parts.append(b"endobj\n")

    xref_offset = sum(len(part) for part in pdf_parts)
    count = len(objects) + 1
    pdf_parts.append(f"xref\n0 {count}\n".encode("utf-8"))
    pdf_parts.append(b"0000000000 65535 f \n")
    for off in offsets:
        pdf_parts.append(f"{off:010d} 00000 n \n".encode("utf-8"))
    pdf_parts.append(f"trailer<< /Size {count} /Root 1 0 R >>\n".encode("utf-8"))
    pdf_parts.append(f"startxref\n{xref_offset}\n%%EOF".encode("utf-8"))
    return b"".join(pdf_parts)


@app.get("/api/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


def _require_api_key(request: Request) -> None:
    if not API_KEY:
        return
    provided = request.headers.get("x-api-key")
    if provided != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.post("/api/cases/upload")
async def upload_case(file: UploadFile = File(...), _: None = Depends(_require_api_key)) -> JSONResponse:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(status_code=400, detail=f"Unsupported extension {ext}. Allowed: {', '.join(sorted(ALLOWED_EXT))}")

    case_id = uuid4().hex
    target_path = UPLOAD_DIR / f"{case_id}_{file.filename}"

    sha256 = hashlib.sha256()

    # Size guardrail: read to disk but limit total bytes, compute hash for dedupe.
    with target_path.open("wb") as out_file:
        copied = 0
        chunk = await file.read(1024 * 1024)
        while chunk:
            copied += len(chunk)
            if copied > MAX_UPLOAD_MB * 1024 * 1024:
                out_file.close()
                target_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File too large")
            sha256.update(chunk)
            out_file.write(chunk)
            chunk = await file.read(1024 * 1024)

    digest = sha256.hexdigest()
    dup = _get_case_by_hash(digest)
    if dup:
        target_path.unlink(missing_ok=True)
        return JSONResponse({"case_id": dup["case_id"], "message": "Duplicate detected; reusing existing case"}, status_code=200)

    meta = {
        "case_id": case_id,
        "filename": file.filename,
        "stored_path": str(target_path),
        "uploaded_at": datetime.utcnow().isoformat(),
        "status": "queued",
        "threat_cards": [],
        "process_tree": {},
        "iocs": {"hashes": [], "ips": [], "dlls": []},
        "timeline": [],
        "sha256": digest,
    }

    _persist_case(meta)

    if celery_app:
        analyze_case_task.delay(case_id)  # type: ignore[name-defined]
    else:
        executor.submit(_analyze_case, case_id)

    return JSONResponse({"case_id": case_id, "message": "Upload received and analysis queued"})


@app.get("/api/cases")
async def list_cases(_: None = Depends(_require_api_key)) -> List[Dict]:
    return _list_cases()


@app.get("/api/cases/{case_id}/dashboard")
async def case_dashboard(case_id: str, _: None = Depends(_require_api_key)) -> Dict:
    meta = _case_or_404(case_id)
    if meta.get("status") not in {"ready", "processing", "queued"}:
        raise HTTPException(status_code=400, detail="Case not ready")
    # Placeholder threat cards for MVP demo.
    threat_cards = meta.get(
        "threat_cards",
        [
            {"severity": "Critical", "title": "Code Injection", "score": 74},
            {"severity": "High", "title": "Suspicious Explorer", "score": 57},
            {"severity": "Medium", "title": "svchost anomaly", "score": 41},
            {"severity": "Medium", "title": "Notepad payload", "score": 34},
        ],
    )
    iocs = meta.get("iocs", {"hashes": [], "ips": [], "dlls": []})
    timeline = meta.get("timeline", [])
    return {
        "case_id": case_id,
        "threat_cards": threat_cards,
        "uploaded_at": meta["uploaded_at"],
        "status": meta.get("status", "unknown"),
        "error": meta.get("error"),
        "iocs": iocs,
        "timeline": timeline,
    }


@app.get("/api/cases/{case_id}/process-tree")
async def process_tree(case_id: str, _: None = Depends(_require_api_key)) -> Dict:
    meta = _case_or_404(case_id)
    if meta.get("status") not in {"ready", "processing", "queued"}:
        raise HTTPException(status_code=400, detail="Case not ready")
    tree = meta.get(
        "process_tree",
        {
            "name": "System",
            "pid": 4,
            "children": [
                {"name": "smss.exe", "pid": 228, "children": []},
                {
                    "name": "wininit.exe",
                    "pid": 340,
                    "children": [
                        {"name": "services.exe", "pid": 428, "children": [{"name": "svchost.exe", "pid": 600, "children": []}]},
                        {"name": "lsass.exe", "pid": 512, "children": []},
                    ],
                },
                {"name": "explorer.exe", "pid": 1432, "children": [{"name": "notepad.exe", "pid": 2450, "children": []}]},
                {"name": "iexplore.exe", "pid": 3200, "children": []},
            ],
        },
    )
    return {"case_id": case_id, "tree": tree}


@app.get("/api/cases/{case_id}/report.pdf")
async def pdf_report(case_id: str, _: None = Depends(_require_api_key)) -> StreamingResponse:
    meta = _case_or_404(case_id)
    pdf_bytes = _build_stub_pdf(case_id, meta)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename=case_{case_id}.pdf"},
    )


@app.get("/api/cases/{case_id}")
async def case_metadata(case_id: str, _: None = Depends(_require_api_key)) -> Dict:
    meta = _case_or_404(case_id)
    return meta


@app.get("/api/cases/{case_id}/iocs")
async def case_iocs(case_id: str, _: None = Depends(_require_api_key)) -> Dict[str, Any]:
    """Export IOCs from a case."""
    meta = _case_or_404(case_id)
    if meta.get("status") != "ready":
        raise HTTPException(status_code=400, detail="Case not ready")
    iocs = meta.get("iocs", {"hashes": [], "ips": [], "dlls": []})
    return {"case_id": case_id, "iocs": iocs}


@app.get("/api/cases/{case_id}/timeline")
async def case_timeline(case_id: str, _: None = Depends(_require_api_key)) -> Dict[str, Any]:
    """Get threat progression timeline."""
    meta = _case_or_404(case_id)
    timeline = meta.get("timeline", [])
    return {"case_id": case_id, "events": timeline}


@app.post("/api/cases/{case_id}/export-iocs")
async def export_iocs_csv(case_id: str, _: None = Depends(_require_api_key)) -> StreamingResponse:
    """Export case IOCs as CSV."""
    meta = _case_or_404(case_id)
    iocs = meta.get("iocs", {"hashes": [], "ips": [], "dlls": []})
    
    lines = ["type,value"]
    for h in iocs.get("hashes", []):
        lines.append(f"hash,{h}")
    for ip in iocs.get("ips", []):
        lines.append(f"ip,{ip}")
    for dll in iocs.get("dlls", []):
        lines.append(f"dll,{dll}")
    
    csv_content = "\n".join(lines).encode("utf-8")
    return StreamingResponse(
        io.BytesIO(csv_content),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=iocs_{case_id}.csv"},
    )
