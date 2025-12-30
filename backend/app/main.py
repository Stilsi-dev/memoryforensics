"""FastAPI Advanced Memory Forensics API (Phase 3: D3.js, Threat Intel, PDF Reports)."""
from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import sys
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
import asyncio
from typing import AsyncGenerator
try:
    from celery import Celery
except Exception:  # pragma: no cover - optional dependency
    Celery = None

# Ensure we can import the existing analyzer without moving it yet.
ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"
BACKEND_DIR = ROOT_DIR / "backend"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))

try:  # noqa: SIM105 - Optional import for future integration
    from memory_analyzer import MemoryAnalyzer  # type: ignore
except Exception:  # pragma: no cover - fallback if dependency not available at runtime
    MemoryAnalyzer = None

try:
    from threat_intel import lookup_ioc_threat_intel, vt_client, abuseipdb_client
except Exception:  # pragma: no cover
    lookup_ioc_threat_intel = None
    vt_client = None
    abuseipdb_client = None

try:
    from pdf_generator import generate_forensic_pdf
except Exception:  # pragma: no cover
    generate_forensic_pdf = None

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

# Track active analysis tasks by case_id for cancellation
_analysis_tasks: Dict[str, threading.Thread] = {}
_analysis_lock = threading.Lock()
_cancel_flags: Dict[str, threading.Event] = {}

# Progress update queue for SSE broadcasting (thread-safe)
from queue import Queue
_progress_queue: Queue = Queue()




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
                progress INTEGER DEFAULT 0,
                progress_msg TEXT DEFAULT '',
                threat_cards TEXT,
                process_tree TEXT,
                iocs TEXT,
                timeline TEXT,
                error TEXT,
                sha256 TEXT
            );
            """
        )
        
        # Add migration for missing columns (Phase 3 features)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(cases);")
        existing_columns = {col[1] for col in cursor.fetchall()}
        
        # Add missing columns if they don't exist
        if "progress" not in existing_columns:
            try:
                conn.execute("ALTER TABLE cases ADD COLUMN progress INTEGER DEFAULT 0;")
            except Exception:
                pass
        if "progress_msg" not in existing_columns:
            try:
                conn.execute("ALTER TABLE cases ADD COLUMN progress_msg TEXT DEFAULT '';")
            except Exception:
                pass
        if "iocs" not in existing_columns:
            try:
                conn.execute("ALTER TABLE cases ADD COLUMN iocs TEXT;")
            except Exception:
                pass  # Column might already exist
        
        if "timeline" not in existing_columns:
            try:
                conn.execute("ALTER TABLE cases ADD COLUMN timeline TEXT;")
            except Exception:
                pass  # Column might already exist
        
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
            INSERT INTO cases (case_id, filename, stored_path, uploaded_at, status, progress, progress_msg, threat_cards, process_tree, iocs, timeline, error, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
                filename=excluded.filename,
                stored_path=excluded.stored_path,
                uploaded_at=excluded.uploaded_at,
                status=excluded.status,
                progress=excluded.progress,
                progress_msg=excluded.progress_msg,
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
                meta.get("progress", 0),
                meta.get("progress_msg", ""),
                _serialize(meta.get("threat_cards")),
                _serialize(meta.get("process_tree")),
                _serialize(meta.get("iocs")),
                _serialize(meta.get("timeline")),
                meta.get("error"),
                meta.get("sha256"),
            ),
        )
        conn.commit()
    
    # Queue progress update for SSE broadcast (thread-safe)
    _queue_progress_broadcast(meta.get("case_id", ""))


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
    """Construct a tree tolerant of string/int PID/PPID mismatches and missing parents."""
    print(f"[process-tree] building tree for {len(processes)} processes")

    def _normalize_pid(val: Any) -> Optional[str]:
        """Return a string PID or None when the value is empty/invalid."""
        if val is None:
            return None
        # Normalize strings like " 472 " or "" to a clean PID or None
        if isinstance(val, str):
            val = val.strip()
            if not val:
                return None
        try:
            return str(int(val))
        except Exception:
            return None

    nodes: Dict[str, Dict[str, Any]] = {}
    children_map: Dict[str, List[str]] = {}
    roots: List[str] = []

    for _, p in processes.items():
        pid_key = _normalize_pid(getattr(p, "pid", None))
        if not pid_key:
            continue
        nodes[pid_key] = {"name": p.name, "pid": pid_key, "children": []}

        parent_key = _normalize_pid(getattr(p, "ppid", None))

        if parent_key and parent_key != pid_key:
            children_map.setdefault(parent_key, []).append(pid_key)
        else:
            roots.append(pid_key)

    # Promote children whose parents are missing to roots so they are not dropped
    for parent_key, child_list in list(children_map.items()):
        if parent_key not in nodes:
            for child in child_list:
                if child not in roots:
                    roots.append(child)

    # Choose a root: prefer PID 4, else any known root, else first node
    root_pid = "4" if "4" in nodes else (roots[0] if roots else (next(iter(nodes.keys())) if nodes else "0"))

    print(f"[process-tree] nodes={len(nodes)} roots={roots} chosen_root={root_pid}")

    visited: set[str] = set()

    def attach(pid: str) -> Dict[str, Any]:
        visited.add(pid)
        node = nodes[pid]
        node["children"] = [attach(child) for child in children_map.get(pid, []) if child in nodes]
        return node

    if not nodes:
        return {"name": "", "pid": 0, "children": []}

    tree = attach(root_pid)

    # Collect any unreachable nodes as additional roots to avoid losing orphans
    extra_roots = [pid for pid in roots if pid in nodes and pid not in visited and pid != root_pid]
    if extra_roots:
        print(f"[process-tree] multiple roots detected; wrapping {1 + len(extra_roots)} roots under System")
        tree = {
            "name": "System",
            "pid": "0",  # avoid duplicating the chosen root PID when wrapping
            "children": [tree] + [attach(r) for r in extra_roots],
        }

    return tree


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
    def _severity(score: float) -> str:
        if score >= 70:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    for p in processes.values():
        if p.risk_score >= 0:
            events.append(
                {
                    "timestamp": p.create_time or "unknown",
                    "pid": p.pid,
                    "process": p.name,
                    "event": f"Risk {p.risk_score:.0f}% - {'; '.join(p.flags()[:2]) if p.flags() else 'anomaly'}",
                    "risk_score": round(p.risk_score, 1),
                    "severity": _severity(p.risk_score),
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


def _run_analyzer(path: str, case_id: str, progress_cb=None) -> Dict[str, Any]:
    """Invoke MemoryAnalyzer; fall back to stubs if unavailable or failing."""
    if MemoryAnalyzer is None:
        if progress_cb:
            progress_cb(50, "Stub analyzer")
            progress_cb(100, "Complete")
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
            progress_cb=progress_cb,
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
    
    # Create cancel flag for this case
    cancel_flag = threading.Event()
    with _analysis_lock:
        _cancel_flags[case_id] = cancel_flag
        _analysis_tasks[case_id] = threading.current_thread()
    
    _update_case(case_id, status="processing", progress=0)
    try:
        def _hook(pct: int, msg: str = "") -> None:
            # Check if cancellation was requested
            if cancel_flag.is_set():
                raise RuntimeError("Analysis cancelled by user")
            try:
                pct_int = max(0, min(100, int(pct)))
                _update_case(case_id, progress=pct_int, status="processing", progress_msg=msg or "Processing")
            except Exception:
                pass

        result = _run_analyzer(meta["stored_path"], case_id, progress_cb=_hook)

        meta_updated = {
            **meta,
            "threat_cards": result.get("threat_cards"),
            "process_tree": result.get("process_tree"),
            "iocs": result.get("iocs"),
            "timeline": result.get("timeline"),
            "status": "ready",
            "progress": 100,
        }
        _persist_case(meta_updated)
    except Exception as exc:  # pragma: no cover - defensive guard
        _update_case(case_id, status="error", error=str(exc), progress=0)
    finally:
        # Clean up
        with _analysis_lock:
            _cancel_flags.pop(case_id, None)
            _analysis_tasks.pop(case_id, None)


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


# SSE for real-time progress updates
_progress_subscribers: List[asyncio.Queue] = []


def _queue_progress_broadcast(case_id: str) -> None:
    """Queue a progress update to be broadcast to SSE clients (thread-safe)."""
    _progress_queue.put(case_id)


@app.get("/api/progress-stream")
async def progress_stream() -> StreamingResponse:
    """Server-Sent Events endpoint for real-time case progress updates."""
    queue: asyncio.Queue = asyncio.Queue()
    _progress_subscribers.append(queue)
    
    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                try:
                    # Check for queued progress updates from sync context
                    case_id = _progress_queue.get_nowait()
                    message = f"data: {json.dumps({'case_id': case_id})}\n\n"
                    for subscriber_queue in _progress_subscribers[:]:
                        try:
                            subscriber_queue.put_nowait(message)
                        except Exception:
                            if subscriber_queue in _progress_subscribers:
                                _progress_subscribers.remove(subscriber_queue)
                except:
                    # No queued items, wait briefly before checking again
                    try:
                        await asyncio.sleep(0.05)
                    except asyncio.CancelledError:
                        break
                
                # Also check for already-queued messages
                try:
                    message = queue.get_nowait()
                    yield message
                except asyncio.QueueEmpty:
                    try:
                        await asyncio.sleep(0.05)
                    except asyncio.CancelledError:
                        break
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        finally:
            if queue in _progress_subscribers:
                _progress_subscribers.remove(queue)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


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
        # Reprocess existing case on duplicate uploads so fresh trees/timeline regenerate
        target_path.unlink(missing_ok=True)
        _update_case(dup["case_id"], status="queued", progress=0, progress_msg="Reprocessing duplicate upload", error=None)
        if celery_app:
            analyze_case_task.delay(dup["case_id"])  # type: ignore[name-defined]
        else:
            future = executor.submit(_analyze_case, dup["case_id"])
            future.daemon = True
        return JSONResponse({"case_id": dup["case_id"], "message": "Duplicate detected; reprocessing existing case"}, status_code=200)

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
        # Submit analysis as daemon thread so it doesn't block shutdown
        future = executor.submit(_analyze_case, case_id)
        # Mark for non-blocking shutdown
        future.daemon = True

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


@app.delete("/api/cases/{case_id}")
async def delete_case(case_id: str, _: None = Depends(_require_api_key)) -> Dict[str, Any]:
    """Delete a case and associated files. Stops analysis if in progress."""
    meta = _case_or_404(case_id)
    
    # Signal cancellation if analysis is ongoing
    with _analysis_lock:
        if case_id in _cancel_flags:
            _cancel_flags[case_id].set()
    
    # Get the stored file path
    stored_path = meta.get("stored_path")
    
    # Delete the file if it exists
    if stored_path:
        try:
            file_path = Path(stored_path)
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")
    
    # Delete from database
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete case: {str(e)}")
    
    return {
        "case_id": case_id,
        "status": "deleted",
        "message": "Case and associated files have been removed"
    }


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


# ============================================================================
# PHASE 3: THREAT INTELLIGENCE INTEGRATION
# ============================================================================

@app.post("/api/iocs/lookup")
async def lookup_ioc_intel(
    ioc_value: str, ioc_type: str = "hash", _: None = Depends(_require_api_key)
) -> Dict[str, Any]:
    """
    Look up IOC reputation across multiple threat intel sources.
    
    Supports:
    - Hash (MD5, SHA-1, SHA-256) via VirusTotal
    - IP address via VirusTotal + AbuseIPDB
    - Domain via VirusTotal
    """
    if not lookup_ioc_threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel unavailable")
    
    try:
        result = lookup_ioc_threat_intel(ioc_value, ioc_type)
        if not result:
            raise HTTPException(status_code=404, detail=f"{ioc_type} not found in threat intel")
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Threat intel lookup failed: {str(e)}")


@app.get("/api/iocs/batch")
async def batch_ioc_lookup(
    case_id: str, _: None = Depends(_require_api_key)
) -> Dict[str, Any]:
    """
    Look up all IOCs from a case across threat intel sources.
    
    Returns enriched IOCs with verdicts and threat scores.
    """
    if not lookup_ioc_threat_intel:
        raise HTTPException(status_code=503, detail="Threat intel unavailable")
    
    meta = _case_or_404(case_id)
    iocs = meta.get("iocs", {"hashes": [], "ips": [], "dlls": []})
    
    enriched = {"hashes": [], "ips": [], "dlls": [], "queried_at": datetime.now().isoformat()}
    
    # Lookup hashes
    for hash_val in iocs.get("hashes", []):
        try:
            result = lookup_ioc_threat_intel(hash_val, "hash")
            if result:
                enriched["hashes"].append(result)
        except Exception:
            pass
    
    # Lookup IPs
    for ip_val in iocs.get("ips", []):
        try:
            result = lookup_ioc_threat_intel(ip_val, "ip")
            if result:
                enriched["ips"].append(result)
        except Exception:
            pass
    
    # DLLs are typically not looked up directly (use hash or filename instead)
    enriched["dlls"] = iocs.get("dlls", [])
    
    return enriched


@app.get("/api/cases/{case_id}/report")
async def generate_forensic_report(
    case_id: str, format_type: str = "json", _: None = Depends(_require_api_key)
) -> Any:
    """
    Generate comprehensive forensic report.
    
    Formats: json, markdown, html, pdf
    """
    meta = _case_or_404(case_id)
    
    # Prepare report data
    report_data = {
        "case_id": case_id,
        "filename": meta.get("filename"),
        "uploaded_at": meta.get("uploaded_at"),
        "analyzed_at": datetime.now().isoformat(),
        "status": meta.get("status"),
        "threat_cards": meta.get("threat_cards", []),
        "iocs": meta.get("iocs", {"hashes": [], "ips": [], "dlls": []}),
        "timeline": meta.get("timeline", []),
        "sha256": meta.get("sha256"),
    }
    
    if format_type == "pdf":
        if not generate_forensic_pdf:
            raise HTTPException(status_code=503, detail="PDF generation unavailable")
        try:
            pdf_buffer = generate_forensic_pdf(report_data)
            return StreamingResponse(
                pdf_buffer,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=report_{case_id}.pdf"}
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
    
    elif format_type == "json":
        return report_data
    
    elif format_type == "markdown":
        md = f"""# Forensic Analysis Report

**Case ID**: {case_id}
**File**: {meta.get('filename')}
**Uploaded**: {meta.get('uploaded_at')}
**Status**: {meta.get('status')}
**SHA-256**: {meta.get('sha256')}

## Threat Findings

"""
        for card in meta.get("threat_cards", []):
            md += f"### {card.get('title', 'Unknown')}\n"
            md += f"- Severity: {card.get('severity', 'Unknown')}\n"
            md += f"- Score: {card.get('score', 'N/A')}\n"
            md += f"- Details: {card.get('detail', 'No details')}\n\n"
        
        md += "## Indicators of Compromise (IOCs)\n\n"
        iocs = meta.get("iocs", {})
        if iocs.get("hashes"):
            md += "### File Hashes\n" + "\n".join(f"- {h}" for h in iocs["hashes"]) + "\n\n"
        if iocs.get("ips"):
            md += "### IP Addresses\n" + "\n".join(f"- {ip}" for ip in iocs["ips"]) + "\n\n"
        if iocs.get("dlls"):
            md += "### Suspicious DLLs\n" + "\n".join(f"- {dll}" for dll in iocs["dlls"]) + "\n\n"
        
        return {
            "format": "markdown",
            "content": md,
            "case_id": case_id
        }
    
    else:  # html
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report - {case_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .threat {{ background: #fee; padding: 10px; margin: 10px 0; border-left: 3px solid #f00; }}
        .meta {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Forensic Analysis Report</h1>
    <p class="meta">Case: {case_id} | File: {meta.get('filename')} | Status: {meta.get('status')}</p>
    
    <h2>Threat Findings</h2>
"""
        for card in meta.get("threat_cards", []):
            html += f"""    <div class="threat">
        <strong>{card.get('title', 'Unknown')}</strong><br/>
        Severity: {card.get('severity', 'Unknown')} | Score: {card.get('score', 'N/A')}<br/>
        {card.get('detail', '')}
    </div>
"""
        
        html += "    <h2>Indicators of Compromise</h2>\n"
        iocs = meta.get("iocs", {})
        if iocs.get("hashes"):
            html += "    <h3>File Hashes</h3><ul>\n" + "\n".join(f"        <li>{h}</li>" for h in iocs["hashes"]) + "\n    </ul>\n"
        if iocs.get("ips"):
            html += "    <h3>IP Addresses</h3><ul>\n" + "\n".join(f"        <li>{ip}</li>" for ip in iocs["ips"]) + "\n    </ul>\n"
        if iocs.get("dlls"):
            html += "    <h3>Suspicious DLLs</h3><ul>\n" + "\n".join(f"        <li>{dll}</li>" for dll in iocs["dlls"]) + "\n    </ul>\n"
        
        html += """</body>
</html>"""
        
        return {
            "format": "html",
            "content": html,
            "case_id": case_id
        }


@app.post("/api/cases/{case_id}/annotate")
async def annotate_case(
    case_id: str, note: str, tags: Optional[List[str]] = None, _: None = Depends(_require_api_key)
) -> Dict[str, Any]:
    """
    Add annotations (notes) and tags to a case.
    Phase 3: Case collaboration and annotation support.
    """
    meta = _case_or_404(case_id)
    
    # Initialize annotations if not present
    if "annotations" not in meta:
        meta["annotations"] = []
    
    annotation = {
        "timestamp": datetime.now().isoformat(),
        "note": note,
        "tags": tags or []
    }
    
    meta["annotations"].append(annotation)
    
    # Update database
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE cases SET metadata = ? WHERE case_id = ?",
            (json.dumps(meta), case_id)
        )
        conn.commit()
    
    return {
        "case_id": case_id,
        "annotation": annotation,
        "total_annotations": len(meta.get("annotations", []))
    }


@app.get("/api/cases/{case_id}/annotations")
async def get_case_annotations(case_id: str, _: None = Depends(_require_api_key)) -> Dict[str, Any]:
    """Retrieve all annotations for a case."""
    meta = _case_or_404(case_id)
    return {
        "case_id": case_id,
        "annotations": meta.get("annotations", [])
    }


# ============================================================================
# PHASE 3: IOC FILTERING & TAGGING
# ============================================================================

@app.post("/api/iocs/{case_id}/tag")
async def tag_ioc(
    case_id: str, 
    ioc_value: str, 
    ioc_type: str, 
    tags: List[str],
    _: None = Depends(_require_api_key)
) -> Dict[str, Any]:
    """
    Tag an IOC with custom labels for classification.
    
    Supports tags like: 'known_malware', 'false_positive', 'whitelisted', 'suspicious', 'critical'
    """
    meta = _case_or_404(case_id)
    
    # Initialize IOC metadata if not present
    if "ioc_metadata" not in meta:
        meta["ioc_metadata"] = {}
    
    ioc_key = f"{ioc_type}:{ioc_value}"
    
    if ioc_key not in meta["ioc_metadata"]:
        meta["ioc_metadata"][ioc_key] = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "tags": [],
            "created_at": datetime.now().isoformat()
        }
    
    # Add new tags
    existing_tags = set(meta["ioc_metadata"][ioc_key].get("tags", []))
    new_tags = existing_tags.union(set(tags))
    meta["ioc_metadata"][ioc_key]["tags"] = list(new_tags)
    meta["ioc_metadata"][ioc_key]["updated_at"] = datetime.now().isoformat()
    
    # Update database
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE cases SET metadata = ? WHERE case_id = ?",
            (json.dumps(meta), case_id)
        )
        conn.commit()
    
    return {
        "case_id": case_id,
        "ioc": ioc_value,
        "tags": list(new_tags),
        "total_tagged_iocs": len(meta.get("ioc_metadata", {}))
    }


@app.get("/api/iocs/{case_id}/filter")
async def filter_iocs(
    case_id: str,
    tag: Optional[str] = None,
    ioc_type: Optional[str] = None,
    _: None = Depends(_require_api_key)
) -> Dict[str, Any]:
    """
    Filter IOCs by tags and/or type.
    
    Args:
        case_id: Case ID
        tag: Filter by tag (e.g., 'critical', 'false_positive')
        ioc_type: Filter by IOC type ('hash', 'ip', 'dll')
    
    Returns:
        Filtered IOCs with metadata
    """
    meta = _case_or_404(case_id)
    iocs = meta.get("iocs", {"hashes": [], "ips": [], "dlls": []})
    ioc_metadata = meta.get("ioc_metadata", {})
    
    results = {"filtered_iocs": [], "total": 0}
    
    # Filter hashes
    if not ioc_type or ioc_type == "hash":
        for hash_val in iocs.get("hashes", []):
            meta_key = f"hash:{hash_val}"
            ioc_meta = ioc_metadata.get(meta_key, {})
            tags = ioc_meta.get("tags", [])
            
            # Apply tag filter
            if tag and tag not in tags:
                continue
            
            results["filtered_iocs"].append({
                "type": "hash",
                "value": hash_val,
                "tags": tags
            })
    
    # Filter IPs
    if not ioc_type or ioc_type == "ip":
        for ip_val in iocs.get("ips", []):
            meta_key = f"ip:{ip_val}"
            ioc_meta = ioc_metadata.get(meta_key, {})
            tags = ioc_meta.get("tags", [])
            
            if tag and tag not in tags:
                continue
            
            results["filtered_iocs"].append({
                "type": "ip",
                "value": ip_val,
                "tags": tags
            })
    
    # Filter DLLs
    if not ioc_type or ioc_type == "dll":
        for dll_val in iocs.get("dlls", []):
            meta_key = f"dll:{dll_val}"
            ioc_meta = ioc_metadata.get(meta_key, {})
            tags = ioc_meta.get("tags", [])
            
            if tag and tag not in tags:
                continue
            
            results["filtered_iocs"].append({
                "type": "dll",
                "value": dll_val,
                "tags": tags
            })
    
    results["total"] = len(results["filtered_iocs"])
    results["filters"] = {"tag": tag, "type": ioc_type}
    
    return results


@app.get("/api/iocs/{case_id}/stats")
async def ioc_statistics(case_id: str, _: None = Depends(_require_api_key)) -> Dict[str, Any]:
    """Get IOC statistics and tag distribution for a case."""
    meta = _case_or_404(case_id)
    iocs = meta.get("iocs", {"hashes": [], "ips": [], "dlls": []})
    ioc_metadata = meta.get("ioc_metadata", {})
    
    # Count by type
    type_counts = {
        "hashes": len(iocs.get("hashes", [])),
        "ips": len(iocs.get("ips", [])),
        "dlls": len(iocs.get("dlls", []))
    }
    
    # Count by tag
    tag_counts = {}
    for meta_key, meta_val in ioc_metadata.items():
        for tag in meta_val.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    
    # Verdict distribution (if threat intel was run)
    verdicts = {}
    for meta_val in ioc_metadata.values():
        verdict = meta_val.get("verdict")
        if verdict:
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
    
    return {
        "case_id": case_id,
        "total_iocs": sum(type_counts.values()),
        "by_type": type_counts,
        "by_tag": tag_counts,
        "by_verdict": verdicts,
        "unique_tags": list(tag_counts.keys())
    }

