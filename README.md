# VibeCheck AI (BrainRot Guard)

A local-first security control plane that protects document-ingesting AI
agents (resume screeners, RAG pipelines, agentic tool-callers) from
**indirect prompt injection** hidden inside PDFs, plus a last-line-of-defense
**egress circuit breaker** that stops a hijacked agent from actually running
a dangerous OS command.

## What was fixed / made real vs. the original spec

| Area | Original spec | What changed |
|---|---|---|
| Zero-width chars in test PDF | `reportlab` base fonts (Helvetica) use 8-bit WinAnsi encoding | Registered a real Unicode TTF (DejaVu Sans) so `\u200B`/`\u200C` actually land in the PDF content stream — otherwise they were silently dropped and the detector had nothing to catch |
| "<0.2ms" circuit breaker claim | Stated as a fixed number | Now **measured per call** with `time.perf_counter()` and reported honestly (typically ~0.01ms for a regex scan, but this varies by hardware/load — we don't hardcode a marketing number) |
| Vector engine without GPU/model download | Assumed `sentence-transformers` always present | Added a deterministic hashed bag-of-words **fallback scorer** so the whole pipeline runs end-to-end without a ~90MB model download; the UI clearly labels which backend is active |
| BLE "hardware-free" sync | Implied it works without hardware | Split into two honest layers: (1) `bleak` **transport**, which genuinely requires a real Bluetooth adapter and will not fake success without one, and (2) the **cryptographic handshake** (X25519 + Ed25519 + HKDF + AES-256-GCM), which is real, hardware-independent, and fully testable on its own |
| Adversarial payload | Described as containing a live curl exploit | It's a documented **inert test fixture** (same idea as an EICAR test file) — the string is never executed by the generator itself, only used to validate detection |

## Architecture / detection flow

```
PDF in → parser.py → vector_engine.py → [decision] → circuit_breaker.py (defense-in-depth)
         (unmask)     (score threat)
```

1. **`parser.py`** — reads the PDF at the character-object layer via
   `pdfplumber` (font size, fill color per glyph), not the rendered page.
   Flags glyphs at ≤1.5pt or near-white color as hidden, strips zero-width
   Unicode characters, and regex-matches known attack phrasing
   (instruction overrides, command execution, credential exfiltration,
   forced-score directives).

2. **`vector_engine.py`** — embeds the extracted text and scores it against
   a `chromadb` collection of threat exemplars by cosine similarity:
   - **< 0.40 → SAFE**, forwarded to the downstream LLM/agent.
   - **0.40–0.85 → AMBIGUOUS**, routed to a human reviewer instead of an
     automated allow/block decision — this is what catches things a
     literal regex would miss (paraphrased jailbreaks) without
     auto-blocking legitimate borderline content.
   - **> 0.85 → CRITICAL**, quarantined and stripped before the LLM ever
     sees it.

3. **`circuit_breaker.py`** — even if a novel/unrecognized injection slips
   past step 2 and gets an agent to *decide* to run a shell command, this
   monkey-patches `subprocess.Popen` to inspect the command against known
   dangerous patterns (`curl`, `wget`, `bash -c`, `rm -rf`, `eval(`, etc.)
   and raises `SecurityException` before the OS spawns the process.

### How a genuinely new/novel injection is handled

- If it's phrased differently from anything in the threat collection but is
  still *semantically* similar (e.g. a paraphrase of "ignore prior
  instructions"), the embedding model still places it near the existing
  cluster in vector space → still caught by the cosine threshold. This is
  the actual advantage of embeddings over keyword lists.
- If it's different enough to land in the AMBIGUOUS band, it goes to human
  review instead of silently passing through.
- Once a human confirms a new attack pattern, add it to `THREAT_EXEMPLARS`
  in `vector_engine.py` (or sync it in from a peer via `ble_mesh.py`) and
  it becomes a first-class detection target going forward — this is what
  the BLE mesh sync is for: propagating newly-confirmed threat vectors
  across machines without a central server.
- If it never touches the document/text layer at all and instead tries to
  get the agent to run a command directly, `circuit_breaker.py` is the
  backstop regardless of whether the vector engine ever saw it.

## What's real, what's a documented fallback

- **Real, no dependencies beyond what's installed**: PDF generation,
  character-layer parsing, regex threat matching, subprocess interception,
  and the full X25519/Ed25519/AES-256-GCM crypto stack.
- **Real, but requires the packages in `requirements.txt`** (needs internet
  access to install): semantic embedding via `sentence-transformers`, and
  persistent vector storage via `chromadb`.
- **Real, but requires physical Bluetooth hardware**: the actual BLE
  discovery/transport in `ble_mesh.py`'s `scan_for_peers()`. This is not
  something any software can honestly fake — the code raises a clear error
  rather than pretending to find a peer.

## Setup

```bash
chmod +x run.sh
./run.sh
```

This creates a virtualenv, installs `requirements.txt`, generates the
adversarial test fixture, and launches the Streamlit UI. First install may
take a few minutes since `sentence-transformers` pulls in PyTorch.

## Manual test of each module

```bash
python3 create_payload.py     # generates adversarial_resume.pdf
python3 parser.py adversarial_resume.pdf
python3 vector_engine.py
python3 circuit_breaker.py
python3 ble_mesh.py
```

## Security note

`create_payload.py` produces a **test fixture only** — the embedded string
is never executed by any code in this repo. It exists so the detection
pipeline has a known-bad sample to validate against, the same role an
EICAR file plays for antivirus testing.
