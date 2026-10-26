# Security and trust model

ProofChain is a document-integrity prototype. It uses SHA-256 with domain-separated leaf and internal-node hashes. An inclusion proof establishes that the canonical document bytes lead to a particular Merkle root.

## What the proof establishes

Given a trusted root, the verifier can establish that the checked document is included in the batch represented by that root. A changed document, an altered path, or a different published root should fail verification.

The local verifier reads the document, proof, root, and optional anchor log. It does not read the SQLite registry. The static browser verifier also keeps inputs in the browser and does not send them to a server.

## What it does not establish

- The identity or authority of the person who registered a document.
- The truth, legality, or authenticity of the document's contents.
- A reliable publication time. The anchor log timestamp is the registry machine's clock.
- That the registry database or anchor log is immutable.
- A trustworthy root if the only copy comes from the same registry operator.

## Pinning roots

The anchor log links each entry to its predecessor and detects edits within the log. A rewritten or truncated log can still form a different valid chain. Record the chain head somewhere the registry operator cannot rewrite, and supply it with the verifier's --head option. Distribute the batch root through a separately controlled channel when independent verification matters.

## Operational guidance

Treat the registry database and anchor log as replaceable local files. Keep backups and publish roots or pinned heads independently. Avoid using this prototype as the sole record-keeping or identity system for high-stakes documents. No private document should be submitted to a website unless you have reviewed and trust that website; the bundled Pages demo is static and performs its checks in the browser.
