"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        import time
        req_id = request_id or f"{user_id}_{len(self.logs)}_{time.time()}"
        self._open[req_id] = {
            "request_id": req_id,
            "user_id": user_id,
            "input": text,
            "start_time": time.time(),
            "timestamp": utc_now_iso(),
        }
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        import time
        req_id = request_id
        entry = None
        if req_id and req_id in self._open:
            entry = self._open.pop(req_id)
        else:
            # find by user_id if any open
            for k, v in list(self._open.items()):
                if v["user_id"] == user_id:
                    entry = self._open.pop(k)
                    req_id = k
                    break

        now = time.time()
        start = entry["start_time"] if entry else now
        latency_ms = round((now - start) * 1000, 2)
        input_text = entry["input"] if entry else ""
        timestamp = entry["timestamp"] if entry else utc_now_iso()

        log_record = {
            "request_id": req_id or f"{user_id}_{len(self.logs)}",
            "timestamp": timestamp,
            "user_id": user_id,
            "input": input_text,
            "response": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(log_record)
        return log_record

    def export_json(self, filepath: str | None = None) -> Path:
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
