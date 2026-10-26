"""Independent ProofChain verifier. Uses only the Python standard library."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
_ENTRY_FIELDS = ("seq", "batch_id", "root", "count", "ts")


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON number: {value}")


def _normalize_json(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in result:
                raise ValueError("two JSON keys become identical after Unicode normalization")
            result[normalized_key] = _normalize_json(item)
        return result
    if isinstance(value, float):
        raise ValueError("floating-point JSON values are not supported for canonical records")
    return value


def canonicalize(data: bytes, kind: str) -> bytes:
    """Return the documented canonical form for bytes, text, or JSON records."""
    if kind == "bytes":
        return data
    if kind == "text":
        text = unicodedata.normalize("NFC", data.decode("utf-8"))
        return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    if kind == "json":
        parsed = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        normalized = _normalize_json(parsed)
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    raise ValueError(f"unknown canonicalization kind: {kind}")


def leaf_hash(canonical_document: bytes) -> bytes:
    return sha(b"\x00" + canonical_document)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha(b"\x01" + left + right)


def fold(leaf: bytes, proof_path: list[Any]) -> bytes:
    current = leaf
    if not isinstance(proof_path, list):
        raise ValueError("proof path must be a list")
    for step in proof_path:
        if not isinstance(step, (list, tuple)) or len(step) != 2:
            raise ValueError("each proof step must contain a side and sibling hash")
        side, sibling_hex = step
        if side not in ("L", "R") or not isinstance(sibling_hex, str):
            raise ValueError("proof step has an invalid side or sibling hash")
        try:
            sibling = bytes.fromhex(sibling_hex)
        except ValueError as exc:
            raise ValueError("proof sibling is not hexadecimal") from exc
        if len(sibling) != 32:
            raise ValueError("proof sibling must be a 32-byte hash")
        current = node_hash(sibling, current) if side == "L" else node_hash(current, sibling)
    return current


def entry_hash(previous: str, entry: dict[str, Any]) -> str:
    body = {key: entry[key] for key in _ENTRY_FIELDS}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((previous + "|" + encoded).encode("utf-8")).hexdigest()


def check_anchor_chain(
    entries: list[Any], pinned_head: str | None = None
) -> tuple[bool, str, str]:
    """Check sequence, links, entry hashes, and an optional out-of-band pinned head."""
    previous = GENESIS
    if not isinstance(entries, list):
        return False, "ANCHOR_LOG_TAMPERED", "anchor log must contain a list of entries"
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return False, "ANCHOR_LOG_TAMPERED", f"entry {index} is not an object"
        try:
            expected_hash = entry_hash(previous, entry)
            valid = (
                entry.get("seq") == index
                and entry.get("prev") == previous
                and entry.get("entry_hash") == expected_hash
            )
        except (KeyError, TypeError, ValueError):
            valid = False
        if not valid:
            return False, "ANCHOR_LOG_TAMPERED", f"chain breaks at entry {index}"
        previous = entry["entry_hash"]
    if pinned_head is not None:
        if not isinstance(pinned_head, str) or len(pinned_head) != 64:
            return False, "ANCHOR_LOG_TAMPERED", "pinned head must be a 32-byte hexadecimal hash"
        try:
            bytes.fromhex(pinned_head)
        except ValueError:
            return False, "ANCHOR_LOG_TAMPERED", "pinned head is not hexadecimal"
        if not hmac.compare_digest(previous, pinned_head.lower()):
            return False, "ANCHOR_LOG_TAMPERED", "chain head differs from the pinned head"
    return True, "OK", previous


def result(valid: bool, code: str, detail: str) -> dict[str, Any]:
    return {"valid": valid, "code": code, "detail": detail}


def verify(document: bytes, proof: Any, published_root: str) -> dict[str, Any]:
    """Verify document membership against a root obtained from a trusted source."""
    if not isinstance(proof, dict):
        return result(False, "MALFORMED_PROOF", "proof must be a JSON object")
    if proof.get("version") != 1:
        return result(False, "MALFORMED_PROOF", "unsupported or missing proof version")
    try:
        canonical = canonicalize(document, proof["canon"])
        leaf = leaf_hash(canonical)
    except Exception as exc:
        return result(False, "DOCUMENT_UNPARSEABLE", f"cannot canonicalize document: {exc}")
    proof_leaf = proof.get("leaf_hash")
    if proof_leaf is not None:
        if not isinstance(proof_leaf, str) or not hmac.compare_digest(proof_leaf.lower(), leaf.hex()):
            return result(False, "DOCUMENT_MODIFIED", "document hash does not match the proof")
    try:
        root = fold(leaf, proof["path"])
    except (KeyError, TypeError, ValueError) as exc:
        return result(False, "MALFORMED_PROOF", str(exc))
    claimed_root = proof.get("root")
    if not isinstance(claimed_root, str) or not hmac.compare_digest(root.hex(), claimed_root.lower()):
        return result(False, "INVALID_PROOF", "proof path does not lead to its claimed root")
    if not isinstance(published_root, str):
        return result(False, "ROOT_MISMATCH", "published root must be a hexadecimal string")
    trusted_root = published_root.strip().lower()
    if not hmac.compare_digest(root.hex(), trusted_root):
        return result(False, "ROOT_MISMATCH", "proof root differs from the trusted published root")
    return result(True, "OK", "document belongs to the batch represented by the published root")


def _read_json(path: str) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a document against a ProofChain proof and trusted root."
    )
    parser.add_argument("document", help="path to the document being checked")
    parser.add_argument("proof", help="path to a proof JSON file")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--root", help="trusted published root in hexadecimal")
    source.add_argument("--anchor-log", help="path to the registry anchor log")
    parser.add_argument("--head", help="previously pinned anchor-log head hash")
    args = parser.parse_args(argv)

    try:
        document = Path(args.document).read_bytes()
        proof = _read_json(args.proof)
        if not isinstance(proof, dict):
            print(json.dumps(result(False, "MALFORMED_PROOF", "proof must be a JSON object"), indent=2))
            return 1
        root = args.root
        if args.anchor_log:
            entries = _read_json_lines(args.anchor_log)
            ok, code, detail = check_anchor_chain(entries, args.head)
            if not ok:
                print(json.dumps(result(False, code, detail), indent=2))
                return 1
            matches = [entry for entry in entries if entry.get("batch_id") == proof.get("batch_id")]
            if not matches:
                print(json.dumps(result(False, "ROOT_MISMATCH", "batch is not in the anchor log"), indent=2))
                return 1
            root = matches[0].get("root")
        verification = verify(document, proof, root)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps(result(False, "INPUT_ERROR", str(exc)), indent=2))
        return 2
    print(json.dumps(verification, indent=2))
    return 0 if verification["valid"] else 1


def _read_json_lines(path: str) -> list[Any]:
    entries: list[Any] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid anchor log JSON on line {line_number}") from exc
    return entries


EXPLAIN = {
    "DOCUMENT_MODIFIED": "The checked file does not match the document hash in the proof.",
    "DOCUMENT_UNPARSEABLE": "The file could not be converted into the canonical form named by the proof.",
    "INVALID_PROOF": "The proof path does not lead to the root claimed by the proof.",
    "MALFORMED_PROOF": "The proof is incomplete or has an invalid structure.",
    "ROOT_MISMATCH": "The proof is valid internally, but its root does not match the trusted published root.",
    "ANCHOR_LOG_TAMPERED": "The anchor log was altered, reordered, or rolled back.",
    "STORED_RECORD_MISMATCH": "The registry data no longer matches its published commitment.",
    "BATCH_NOT_PUBLISHED": "The registry contains a batch with no matching anchor entry.",
}


def explain(code: str) -> str:
    """Return advisory wording; this text never affects verification."""
    return EXPLAIN.get(code, "Verification failed.")


if __name__ == "__main__":
    sys.exit(main())
