"""Local SQLite registry that stores records and produces Merkle proofs."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from .verifier import (
    GENESIS,
    canonicalize,
    check_anchor_chain,
    entry_hash,
    leaf_hash,
    node_hash,
)


def build(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        raise ValueError("cannot build a batch with no records")
    levels = [leaves]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append(
            [
                node_hash(current[index], current[index + 1])
                if index + 1 < len(current)
                else current[index]
                for index in range(0, len(current), 2)
            ]
        )
    return levels


def prove(levels: list[list[bytes]], index: int) -> list[tuple[str, str]]:
    if not levels or index < 0 or index >= len(levels[0]):
        raise ValueError("record index is outside the batch")
    path: list[tuple[str, str]] = []
    current_index = index
    for level in levels[:-1]:
        sibling_index = current_index ^ 1
        if sibling_index < len(level):
            side = "L" if sibling_index < current_index else "R"
            path.append((side, level[sibling_index].hex()))
        current_index //= 2
    return path


def read_anchor(path: str | Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid anchor log JSON on line {line_number}") from exc
                if not isinstance(entry, dict):
                    raise ValueError(f"anchor log line {line_number} is not an object")
                entries.append(entry)
    except FileNotFoundError:
        return []
    return entries


def append_anchor(path: str | Path, batch_id: int, root: str, count: int) -> dict[str, Any]:
    entries = read_anchor(path)
    previous = entries[-1]["entry_hash"] if entries else GENESIS
    entry: dict[str, Any] = {
        "seq": len(entries),
        "batch_id": batch_id,
        "root": root,
        "count": count,
        "ts": int(time.time()),
        "prev": previous,
    }
    entry["entry_hash"] = entry_hash(previous, entry)
    with Path(path).open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


class Registry:
    """A local registry; its database and anchor log must be protected separately."""

    def __init__(self, database_path: str | Path, anchor_path: str | Path):
        self.anchor_path = Path(anchor_path)
        self.db = sqlite3.connect(database_path)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS records(
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                doc BLOB NOT NULL,
                leaf TEXT NOT NULL,
                batch_id INTEGER,
                idx INTEGER,
                meta TEXT,
                meta_confirmed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS batches(
                id INTEGER PRIMARY KEY,
                root TEXT NOT NULL,
                count INTEGER NOT NULL
            );
            """
        )

    def __enter__(self) -> "Registry":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        self.db.close()

    def add(self, name: str, data: bytes, kind: str = "bytes") -> int:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("record name must be a non-empty string")
        document = bytes(data)
        leaf = leaf_hash(canonicalize(document, kind)).hex()
        cursor = self.db.execute(
            "INSERT INTO records(name,kind,doc,leaf) VALUES(?,?,?,?)",
            (name.strip(), kind, document, leaf),
        )
        self.db.commit()
        return int(cursor.lastrowid)

    def seal(self) -> tuple[int, str] | None:
        rows = self.db.execute(
            "SELECT id,leaf FROM records WHERE batch_id IS NULL ORDER BY id"
        ).fetchall()
        if not rows:
            return None
        root = build([bytes.fromhex(leaf) for _, leaf in rows])[-1][0].hex()
        cursor = self.db.execute(
            "INSERT INTO batches(root,count) VALUES(?,?)", (root, len(rows))
        )
        batch_id = int(cursor.lastrowid)
        for index, (record_id, _) in enumerate(rows):
            self.db.execute(
                "UPDATE records SET batch_id=?, idx=? WHERE id=?",
                (batch_id, index, record_id),
            )
        self.db.commit()
        append_anchor(self.anchor_path, batch_id, root, len(rows))
        return batch_id, root

    def proof(self, record_id: int) -> dict[str, Any]:
        row = self.db.execute(
            "SELECT kind,leaf,batch_id,idx FROM records WHERE id=?", (record_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"record {record_id} does not exist")
        kind, leaf, batch_id, index = row
        if batch_id is None or index is None:
            raise ValueError(f"record {record_id} has not been sealed into a batch")
        leaves = [
            bytes.fromhex(value)
            for (value,) in self.db.execute(
                "SELECT leaf FROM records WHERE batch_id=? ORDER BY idx", (batch_id,)
            )
        ]
        levels = build(leaves)
        return {
            "version": 1,
            "canon": kind,
            "batch_id": batch_id,
            "index": index,
            "leaf_hash": leaf,
            "path": prove(levels, index),
            "root": levels[-1][0].hex(),
        }

    def audit(self, pinned_head: str | None = None) -> list[tuple[str, str]]:
        findings: list[tuple[str, str]] = []
        try:
            entries = read_anchor(self.anchor_path)
        except (OSError, ValueError) as exc:
            findings.append(("ANCHOR_LOG_TAMPERED", str(exc)))
            entries = []
        ok, code, detail = check_anchor_chain(entries, pinned_head)
        if not ok:
            findings.append((code, detail))
        published = {entry["batch_id"]: entry["root"] for entry in entries if "batch_id" in entry and "root" in entry}
        batches = self.db.execute("SELECT id,root FROM batches").fetchall()
        for batch_id, stored_root in batches:
            rows = self.db.execute(
                "SELECT id,kind,doc,leaf FROM records WHERE batch_id=? ORDER BY idx",
                (batch_id,),
            ).fetchall()
            leaves: list[bytes] = []
            for record_id, kind, document, stored_leaf in rows:
                try:
                    actual_leaf = leaf_hash(canonicalize(document, kind)).hex()
                except Exception as exc:
                    findings.append(("STORED_RECORD_MISMATCH", f"record {record_id}: document cannot be canonicalized: {exc}"))
                    continue
                leaves.append(bytes.fromhex(actual_leaf))
                if actual_leaf != stored_leaf:
                    findings.append(
                        ("STORED_RECORD_MISMATCH", f"record {record_id}: stored leaf differs from document")
                    )
            if batch_id not in published:
                findings.append(("BATCH_NOT_PUBLISHED", f"batch {batch_id}"))
                continue
            if not leaves or build(leaves)[-1][0].hex() != published[batch_id]:
                findings.append(
                    ("STORED_RECORD_MISMATCH", f"batch {batch_id}: stored documents differ from published root")
                )
            if stored_root != published[batch_id]:
                findings.append(
                    ("STORED_RECORD_MISMATCH", f"batch {batch_id}: database root differs from anchor log")
                )
        return findings


def suggest_metadata(text: str) -> dict[str, str | None]:
    """Return unconfirmed metadata suggestions; no suggestion affects a proof."""
    date = re.search(r"\d{4}-\d{2}-\d{2}", text)
    issuer = re.search(r"[Ii]ssued by:?\s*(.+)", text)
    return {
        "issuer": issuer.group(1).strip() if issuer else None,
        "date": date.group(0) if date else None,
    }


def save_suggestion(registry: Registry, record_id: int, metadata: dict[str, Any]) -> None:
    registry.db.execute(
        "UPDATE records SET meta=?, meta_confirmed=0 WHERE id=?",
        (json.dumps(metadata), record_id),
    )
    registry.db.commit()


def confirm_metadata(
    registry: Registry, record_id: int, metadata: dict[str, Any], reviewer: str
) -> None:
    confirmed = {**metadata, "confirmed_by": reviewer}
    registry.db.execute(
        "UPDATE records SET meta=?, meta_confirmed=1 WHERE id=?",
        (json.dumps(confirmed), record_id),
    )
    registry.db.commit()
