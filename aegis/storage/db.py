"""SQLite persistence layer.

A thin, dependency-free wrapper that materialises the schema and provides typed
save/load helpers for the domain objects. SQLite keeps the platform portable and
offline; the schema is written to port cleanly to Postgres for multi-user
deployments.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ..core.types import (
    Evidence,
    Finding,
    Observation,
    Probe,
    ProbeResult,
    new_id,
    now_ts,
)

_SCHEMA = Path(__file__).with_name("schema.sql")


def _dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, ensure_ascii=False)


class Database:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA.read_text(encoding="utf-8"))

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *a) -> None:
        self.close()

    # -- assessments -------------------------------------------------------- #
    def create_assessment(self, engagement: str, config: dict) -> str:
        aid = new_id("assess")
        self.conn.execute(
            "INSERT INTO assessments(id,engagement,status,config_json,started_at) "
            "VALUES(?,?,?,?,?)",
            (aid, engagement, "running", _dumps(config), now_ts()))
        self.conn.commit()
        return aid

    def finish_assessment(self, aid: str, status: str = "completed") -> None:
        self.conn.execute(
            "UPDATE assessments SET status=?, finished_at=? WHERE id=?",
            (status, now_ts(), aid))
        self.conn.commit()

    def add_target(self, aid: str, tid: str, kind: str, mode: str,
                   model: str | None, endpoint: str | None, metadata: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO targets(id,assessment_id,kind,mode,model,endpoint,"
            "metadata_json) VALUES(?,?,?,?,?,?,?)",
            (tid, aid, kind, mode, model, endpoint, _dumps(metadata)))
        self.conn.commit()

    # -- probes / results / evidence --------------------------------------- #
    def save_probe(self, aid: str, probe: Probe) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO probes(id,assessment_id,seed_id,category,mode,"
            "objective,payload_json,provenance_json,content_hash,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (probe.id, aid, probe.seed_id, probe.category.value, probe.mode.value,
             probe.objective, _dumps(probe.payload), _dumps(probe.provenance),
             probe.content_hash, now_ts()))

    def save_result(self, aid: str, result: ProbeResult) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO results(id,probe_id,assessment_id,target_id,status,"
            "response_json,latency_ms,tokens_json,error,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (result.id, result.probe_id, aid, result.target_id, result.status.value,
             _dumps(result.response), result.latency_ms, _dumps(result.tokens),
             result.error, result.created_at))
        for ev in result.evidence:
            self.save_evidence(aid, result.id, ev)

    def save_evidence(self, aid: str, result_id: str | None, ev: Evidence) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO evidence(id,result_id,assessment_id,target_id,kind,"
            "summary,payload_json,reproduction_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (ev.id, result_id, aid, ev.target_id, ev.kind, ev.summary,
             _dumps(ev.payload), _dumps(ev.reproduction), ev.created_at))

    def save_observation(self, aid: str, obs: Observation) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO observations(id,assessment_id,target_id,dimension,"
            "metric,value,unit,direction,confidence_json,evidence_ids_json,context_json,"
            "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (obs.id, aid, obs.context.get("target_id"), obs.dimension, obs.metric,
             obs.value, obs.unit, obs.direction, _dumps(obs.confidence.to_dict()),
             _dumps(obs.evidence_ids), _dumps(obs.context), obs.created_at))

    def save_finding(self, aid: str, f: Finding) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings(id,assessment_id,target_id,title,category,"
            "severity,mode,confidence_json,summary,root_cause,impact,frameworks_json,"
            "mitigations_json,regression_tests_json,evidence_ids_json,observation_ids_json,"
            "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f.id, aid, f.target_id, f.title, f.category.value, f.severity.value,
             f.mode.value, _dumps(f.confidence.to_dict()), f.summary, f.root_cause,
             f.impact, _dumps(f.frameworks), _dumps(f.mitigations),
             _dumps(f.regression_tests), _dumps(f.evidence_ids),
             _dumps(f.observation_ids), f.created_at))

    def save_metric(self, aid: str, name: str, value: float,
                    target_id: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO metrics(id,assessment_id,target_id,name,value,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (new_id("metric"), aid, target_id, name, float(value), now_ts()))

    def _insert_tool_run(self, rec: dict, aid: str | None) -> None:
        self.conn.execute(
            "INSERT INTO tool_runs(id,assessment_id,tool,binary,target,engagement,"
            "requested_by,reason,argv_json,scope_allowed,scope_reason,risk_level,"
            "approved,dry_run,executed,exit_code,duration_s,outcome,detail,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rec["id"], aid, rec["tool"], rec["binary"], rec["target"],
             rec.get("engagement"), rec.get("requested_by"), rec.get("reason"),
             _dumps(rec.get("argv", [])), int(bool(rec["scope_allowed"])),
             rec.get("scope_reason"), rec.get("risk_level"),
             int(bool(rec["approved"])), int(bool(rec["dry_run"])),
             int(bool(rec["executed"])), rec.get("exit_code"),
             rec.get("duration_s"), rec["outcome"], rec.get("detail"),
             rec["created_at"]))

    def save_tool_run(self, rec: dict, aid: str | None = None) -> None:
        """Persist an immutable tool-run audit record (from ToolRunRecord.to_dict()).

        Append-only: the platform never updates or deletes these rows, so the
        audit trail of what was executed (or refused) stays trustworthy.
        """
        self._insert_tool_run(rec, aid)
        self.conn.commit()

    def save_tool_runs(self, records: list[dict], aid: str | None = None) -> None:
        """Persist many tool-run audit records in one transaction (append-only).

        Used by the built-in active probes, which emit one audit record per HTTP
        request — including authorized requests that found nothing and requests
        refused by scope — so the engagement has a complete per-request trail
        alongside the external-tool runs.
        """
        for rec in records:
            self._insert_tool_run(rec, aid)
        self.conn.commit()

    def tool_runs(self, aid: str | None = None) -> list[dict]:
        if aid is None:
            cur = self.conn.execute(
                "SELECT * FROM tool_runs ORDER BY created_at")
        else:
            cur = self.conn.execute(
                "SELECT * FROM tool_runs WHERE assessment_id=? ORDER BY created_at",
                (aid,))
        return [dict(r) for r in cur.fetchall()]

    def commit(self) -> None:
        self.conn.commit()

    # -- reads -------------------------------------------------------------- #
    def findings(self, aid: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM findings WHERE assessment_id=? ORDER BY created_at", (aid,))
        return [dict(r) for r in cur.fetchall()]

    def observations(self, aid: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT * FROM observations WHERE assessment_id=?", (aid,))
        return [dict(r) for r in cur.fetchall()]

    def metrics(self, aid: str) -> list[dict]:
        cur = self.conn.execute("SELECT * FROM metrics WHERE assessment_id=?", (aid,))
        return [dict(r) for r in cur.fetchall()]

    def count(self, table: str, aid: str) -> int:
        cur = self.conn.execute(
            f"SELECT COUNT(*) c FROM {table} WHERE assessment_id=?", (aid,))
        return cur.fetchone()["c"]

    # -- memory / baselines ------------------------------------------------- #
    def mem_put(self, namespace: str, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO memory(id,namespace,key,value_json,created_at) VALUES(?,?,?,?,?)",
            (new_id("mem"), namespace, key, _dumps(value), now_ts()))
        self.conn.commit()

    def mem_get(self, namespace: str, key: str) -> list[Any]:
        cur = self.conn.execute(
            "SELECT value_json FROM memory WHERE namespace=? AND key=? ORDER BY created_at",
            (namespace, key))
        return [json.loads(r["value_json"]) for r in cur.fetchall()]

    def set_baseline(self, target_key: str, dimension: str, metric: str,
                     value: float, tolerance: float = 0.1) -> None:
        self.conn.execute(
            "INSERT INTO baselines(id,target_key,dimension,metric,value,tolerance,created_at) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(target_key,dimension,metric) "
            "DO UPDATE SET value=excluded.value, tolerance=excluded.tolerance, "
            "created_at=excluded.created_at",
            (new_id("base"), target_key, dimension, metric, value, tolerance, now_ts()))
        self.conn.commit()

    def get_baseline(self, target_key: str, dimension: str,
                     metric: str) -> dict | None:
        cur = self.conn.execute(
            "SELECT * FROM baselines WHERE target_key=? AND dimension=? AND metric=?",
            (target_key, dimension, metric))
        row = cur.fetchone()
        return dict(row) if row else None
