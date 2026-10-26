# ProofChain

ProofChain creates local Merkle batches for documents and produces proofs that can be checked independently. It includes a Python command-line tool and a static browser demo. The browser demo processes everything on your device; it does not upload documents.

## What it does

- Canonicalizes raw bytes, UTF-8 text, or JSON before hashing.
- Stores documents and batch metadata in a local SQLite database.
- Builds SHA-256 Merkle roots and per-document inclusion proofs.
- Writes an append-only, hash-chained anchor log.
- Verifies proofs without opening the registry database.
- Checks the anchor log against a root you obtained from a separately trusted source.

The verifier can prove that a document matches a published root. It cannot prove who issued a document, whether its content is true, or when the root was published. For those claims, publish or pin the root somewhere the registry operator cannot silently rewrite.

## Browser demo

Serve the site locally with python -m http.server 8000 --directory site, or use the GitHub Pages site after deployment. Enter one text document per line, create a proof, then edit the document or proof and check the result. The root is shown separately so you can see the difference between a proof's own claim and a trusted root.

## Python quick start

Requires Python 3.10 or newer.

    python -m venv .venv
    .venv\Scripts\activate
    python -m pip install -e .
    proofchain-demo

On macOS or Linux, activate the environment with:

    source .venv/bin/activate

The demo uses a temporary directory and removes it when it exits. It will not overwrite files in the current directory.

## Verify a document

Run the demo to see the format, or create a registry in your own Python code:

    from proofchain import Registry

    with Registry("registry.sqlite3", "anchor.jsonl") as registry:
        record_id = registry.add("certificate.txt", b"Certificate text", kind="text")
        batch_id, root = registry.seal()
        proof = registry.proof(record_id)

Save the returned proof as JSON. The independent verifier accepts either a trusted root or an anchor log:

    proofchain-verify certificate.txt proof.json --root PUBLISHED_ROOT
    proofchain-verify certificate.txt proof.json --anchor-log anchor.jsonl --head PINNED_HEAD

The pinned head must be recorded out of band. Without it, a registry operator could replace the entire anchor log with a different valid chain.

## Canonicalization

- bytes: hashes the exact file bytes.
- text: requires UTF-8, normalizes Unicode to NFC, and changes CRLF or CR line endings to LF.
- json: parses JSON, rejects duplicate keys and floating-point values, normalizes strings to NFC, sorts object keys, and removes insignificant whitespace.

JSON number restrictions avoid ambiguous canonical representations. Choose bytes if the exact file representation is what matters.

## Project layout

- proofchain/ contains the installable Python package.
- site/ contains the static browser demo published by GitHub Pages.
- docs/threat-model.md explains trust assumptions and limitations.
- .github/workflows/pages.yml deploys the site when main changes.

## Development

Install the package locally with python -m pip install -e . No runtime dependencies are required. GitHub Pages serves only the static browser demo; the Python package runs locally and does not require a hosted backend.
