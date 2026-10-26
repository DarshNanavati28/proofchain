"""Run the ProofChain walkthrough in a temporary directory."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .registry import Registry, read_anchor
from .verifier import canonicalize, check_anchor_chain, explain, leaf_hash, verify


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="proofchain-demo-") as temporary_directory:
        database = Path(temporary_directory) / "registry.sqlite3"
        anchor_log = Path(temporary_directory) / "anchor.jsonl"
        with Registry(database, anchor_log) as registry:
            documents = {
                f"cert{index}": (
                    f"Certificate {index}\nIssued by: University X\n2026-01-{index:02d}"
                ).encode("utf-8")
                for index in range(1, 6)
            }
            record_ids = {
                name: registry.add(name, document, "text")
                for name, document in documents.items()
            }
            _, root = registry.seal()
            pinned_head = read_anchor(anchor_log)[-1]["entry_hash"]
            proofs = {
                name: registry.proof(record_id)
                for name, record_id in record_ids.items()
            }

            def show(label: str, outcome: dict[str, object]) -> None:
                print(f"{label:42s} {outcome['code']}")

            print(f"published root {root[:16]} | pinned head {pinned_head[:16]}")
            show("1 honest document", verify(documents["cert3"], proofs["cert3"], root))
            show(
                "2 CRLF text canonicalization",
                verify(documents["cert3"].replace(b"\n", b"\r\n"), proofs["cert3"], root),
            )
            show(
                "3 modified document",
                verify(documents["cert3"] + b"!", proofs["cert3"], root),
            )
            changed_proof = json.loads(json.dumps(proofs["cert3"]))
            changed_proof["path"][0][1] = "00" * 32
            show("4 corrupted proof path", verify(documents["cert3"], changed_proof, root))
            forged_proof = json.loads(json.dumps(proofs["cert3"]))
            forged_proof["root"] = "ab" * 32
            show("5 forged proof root", verify(documents["cert3"], forged_proof, root))
            show("6 wrong published root", verify(documents["cert3"], proofs["cert3"], "cd" * 32))
            show("7 proof for a different document", verify(documents["cert3"], proofs["cert2"], root))

            evil_document = b"Certificate 3\nIssued by: University X\n2030-01-01"
            registry.db.execute(
                "UPDATE records SET doc=?, leaf=? WHERE id=?",
                (
                    evil_document,
                    leaf_hash(canonicalize(evil_document, "text")).hex(),
                    record_ids["cert3"],
                ),
            )
            registry.db.commit()
            print("-- registry database altered --")
            print("audit:", registry.audit(pinned_head))
            show(
                "8 verifier rejects altered document",
                verify(evil_document, registry.proof(record_ids["cert3"]), root),
            )
            show(
                "9 original document still verifies",
                verify(documents["cert3"], proofs["cert3"], root),
            )
            entries = read_anchor(anchor_log)
            entries[0]["root"] = "ee" * 32
            print(
                "10 rewritten anchor log ->",
                check_anchor_chain(entries, pinned_head)[1],
            )
            print("11 rolled-back log ->", check_anchor_chain([], pinned_head)[1])
            print("AI explanation:", explain("ROOT_MISMATCH"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
