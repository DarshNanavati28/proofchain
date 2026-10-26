"use strict";

const encoder = new TextEncoder();
const recordsInput = document.getElementById("records");
const recordIndexInput = document.getElementById("record-index");
const documentInput = document.getElementById("document");
const proofInput = document.getElementById("proof");
const rootInput = document.getElementById("trusted-root");
const buildStatus = document.getElementById("build-status");
const verifyStatus = document.getElementById("verify-status");
const generatedRoot = document.getElementById("generated-root");

function canonicalText(value) {
  return value.normalize("NFC").replace(/\r\n?/g, "\n");
}

function concatBytes(left, right) {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left, 0);
  combined.set(right, left.length);
  return combined;
}

async function digest(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function toHex(bytes) {
  return Array.from(bytes, function (value) {
    return value.toString(16).padStart(2, "0");
  }).join("");
}

function fromHex(value) {
  if (typeof value !== "string" || value.length !== 64 || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error("A proof hash must be 64 hexadecimal characters.");
  }
  const output = new Uint8Array(32);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

async function makeLeaf(text) {
  return digest(concatBytes(new Uint8Array([0]), encoder.encode(canonicalText(text))));
}

async function makeNode(left, right) {
  return digest(concatBytes(concatBytes(new Uint8Array([1]), left), right));
}

async function buildLevels(documents) {
  const levels = [await Promise.all(documents.map(makeLeaf))];
  while (levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next = [];
    for (let index = 0; index < current.length; index += 2) {
      next.push(index + 1 < current.length
        ? await makeNode(current[index], current[index + 1])
        : current[index]);
    }
    levels.push(next);
  }
  return levels;
}

function setStatus(element, message, state) {
  element.textContent = message;
  element.classList.remove("success", "error");
  if (state) element.classList.add(state);
}

document.getElementById("create-proof").addEventListener("click", async function () {
  setStatus(buildStatus, "Creating a proof in this browser…", "");
  try {
    const documents = recordsInput.value.split(/\r?\n/).map(function (line) {
      return line;
    }).filter(function (line) { return line.trim().length > 0; });
    const selectedIndex = Number(recordIndexInput.value) - 1;
    if (documents.length === 0) throw new Error("Add at least one non-empty record.");
    if (!Number.isInteger(selectedIndex) || selectedIndex < 0 || selectedIndex >= documents.length) {
      throw new Error("Choose a record number between 1 and the number of records.");
    }

    const levels = await buildLevels(documents);
    const root = toHex(levels[levels.length - 1][0]);
    const path = [];
    let index = selectedIndex;
    for (const level of levels.slice(0, -1)) {
      const siblingIndex = index ^ 1;
      if (siblingIndex < level.length) {
        path.push([siblingIndex < index ? "L" : "R", toHex(level[siblingIndex])]);
      }
      index = Math.floor(index / 2);
    }

    const proof = {
      version: 1,
      canon: "text",
      batch_id: 1,
      index: selectedIndex,
      leaf_hash: toHex(levels[0][selectedIndex]),
      path: path,
      root: root
    };
    documentInput.value = documents[selectedIndex];
    proofInput.value = JSON.stringify(proof, null, 2);
    rootInput.value = root;
    generatedRoot.textContent = root;
    setStatus(buildStatus, "Proof created locally. The selected record and root are ready to verify.", "success");
    setStatus(verifyStatus, "Compare this proof with a root you trust.", "");
  } catch (error) {
    generatedRoot.textContent = "Create a proof to see the root";
    setStatus(buildStatus, error.message || "Could not create the proof.", "error");
  }
});

document.getElementById("verify-proof").addEventListener("click", async function () {
  setStatus(verifyStatus, "Checking the document and proof…", "");
  try {
    const proof = JSON.parse(proofInput.value);
    if (!proof || typeof proof !== "object" || Array.isArray(proof) || proof.version !== 1) {
      throw new Error("Use a version 1 ProofChain proof.");
    }
    if (proof.canon !== "text" || !Array.isArray(proof.path)) {
      throw new Error("This browser demo verifies text proofs with a path array.");
    }
    const leaf = await makeLeaf(documentInput.value);
    const leafHex = toHex(leaf);
    if (proof.leaf_hash && proof.leaf_hash.toLowerCase() !== leafHex) {
      throw new Error("Document changed: its hash does not match the proof.");
    }
    let current = leaf;
    for (const step of proof.path) {
      if (!Array.isArray(step) || step.length !== 2 || (step[0] !== "L" && step[0] !== "R")) {
        throw new Error("The proof path has an invalid step.");
      }
      const sibling = fromHex(step[1]);
      current = step[0] === "L" ? await makeNode(sibling, current) : await makeNode(current, sibling);
    }
    const computedRoot = toHex(current);
    if (typeof proof.root !== "string" || computedRoot !== proof.root.toLowerCase()) {
      throw new Error("Invalid proof: its path does not produce the root in the proof.");
    }
    const trustedRoot = rootInput.value.trim().toLowerCase();
    if (!trustedRoot || computedRoot !== trustedRoot) {
      throw new Error("Root mismatch: the proof does not match the trusted published root.");
    }
    setStatus(verifyStatus, "Verified. This text belongs to the batch represented by the trusted root.", "success");
  } catch (error) {
    setStatus(verifyStatus, error.message || "The document could not be verified.", "error");
  }
});

for (const input of [recordsInput, documentInput, proofInput, rootInput]) {
  input.addEventListener("input", function () {
    if (input === recordsInput) setStatus(buildStatus, "Input changed. Create a fresh proof to update the root.", "");
    if (input !== recordsInput) setStatus(verifyStatus, "Inputs changed. Run verification again.", "");
  });
}
