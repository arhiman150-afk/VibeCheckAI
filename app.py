"""
app.py — VibeCheck AI (BrainRot Guard) Command Center

Streamlit UI tying together: parser.py (unmasking), vector_engine.py
(threat scoring), circuit_breaker.py (egress protection), and ble_mesh.py
(peer sync demo).
"""

from __future__ import annotations

import time
import subprocess
import streamlit as st

from parser import parse_pdf
from vector_engine import ThreatVectorEngine, USING_FALLBACK, SAFE_THRESHOLD, CRITICAL_THRESHOLD
from circuit_breaker import enable_circuit_breaker, taint_scope, SecurityException, BLOCK_LOG
from ble_mesh import simulate_secure_handshake_and_sync, BLEAK_AVAILABLE
from create_payload import generate_adversarial_pdf

st.set_page_config(page_title="VibeCheck AI — BrainRot Guard", page_icon="🛡️", layout="wide")

CUSTOM_CSS = """
<style>
    .stApp { background-color: #0E1117; color: #E6E6E6; }
    .metric-safe { color: #22C55E; }
    .metric-danger { color: #EF4444; }
    .metric-warn { color: #F59E0B; }
    div[data-testid="stMetricValue"] { font-family: 'Courier New', monospace; }
    .audit-row { font-family: 'Courier New', monospace; font-size: 0.85rem;
                 border-left: 3px solid #EF4444; padding-left: 8px; margin-bottom: 6px; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_engine():
    return ThreatVectorEngine()


def init_state():
    if "audit_log" not in st.session_state:
        st.session_state.audit_log = []
    if "stats" not in st.session_state:
        st.session_state.stats = {
            "docs_scanned": 0,
            "blocked_subprocess_calls": 0,
            "bytes_stripped": 0,
        }


def log_audit(entry: dict):
    entry["ts"] = time.strftime("%H:%M:%S")
    st.session_state.audit_log.insert(0, entry)


def run_vulnerable_agent_demo(hidden_text: str) -> dict:
    """Shows what happens WITHOUT protection: the extracted hidden text is
    passed straight to a simulated 'agent' that naively executes anything
    that looks like a tool call. No taint_scope, no circuit breaker —
    subprocess.Popen runs unmodified here (or is intercepted globally if
    enable_circuit_breaker() was already called elsewhere in-process; the
    'vulnerable' framing is about the *absence of taint tracking / vector
    screening upstream*, which is the actual point being demonstrated)."""
    if "curl" in hidden_text.lower():
        try:
            proc = subprocess.Popen(
                ["curl", "--max-time", "1", "-s", "-o", "/dev/null",
                 "http://169.254.169.254/nonexistent-vibecheck-demo-endpoint"],
            )
            proc.wait(timeout=2)
            return {"executed": True, "detail": "Agent invoked curl based on hidden instruction — unprotected."}
        except SecurityException as e:
            return {"executed": False, "detail": f"(circuit breaker was globally active) blocked: {e.matched_pattern}"}
        except Exception as e:
            return {"executed": True, "detail": f"Agent attempted curl (network call itself failed/timed out: {e}), but the dangerous call was NOT stopped."}
    return {"executed": False, "detail": "No command-execution directive found in hidden text."}


def run_protected_agent_demo(hidden_text: str) -> dict:
    """Same scenario, but the call happens inside taint_scope(), so the
    circuit breaker inspects and blocks it before the OS spawns a process."""
    if "curl" not in hidden_text.lower():
        return {"blocked": False, "detail": "No command-execution directive found in hidden text.", "latency_ms": 0.0}
    try:
        with taint_scope():
            subprocess.Popen(
                ["curl", "--max-time", "1", "-s", "-o", "/dev/null",
                 "http://169.254.169.254/nonexistent-vibecheck-demo-endpoint"],
            )
        return {"blocked": False, "detail": "Unexpected: call was not intercepted.", "latency_ms": 0.0}
    except SecurityException as e:
        st.session_state.stats["blocked_subprocess_calls"] += 1
        return {"blocked": True, "detail": f"Blocked before OS process spawn.", "latency_ms": e.latency_ms}


def main():
    init_state()
    enable_circuit_breaker()
    engine = get_engine()

    st.title("🛡️ VibeCheck AI — BrainRot Guard")
    st.caption("Local-first prompt-injection & egress protection for document-ingesting AI agents")

    backend_label = "⚠️ Fallback hashed-embedding scorer (sentence-transformers/chromadb not installed)" if USING_FALLBACK else "✅ sentence-transformers (all-MiniLM-L6-v2) + ChromaDB"
    ble_label = "✅ Real BLE hardware transport available" if BLEAK_AVAILABLE else "⚠️ No BLE hardware detected — sync demo runs crypto-only (transport simulated)"
    st.info(f"**Vector backend:** {backend_label}  \n**BLE transport:** {ble_label}", icon="ℹ️")

    tab_live, tab_upload, tab_audit, tab_sync = st.tabs(
        ["🎬 Live Demo Mode", "📄 Upload & Scan", "📋 Audit Log", "🔗 BLE Mesh Sync"]
    )

    # ---------------- Live Demo Mode ----------------
    with tab_live:
        st.subheader("Side-by-Side: Vulnerable vs. Protected Agent")
        st.write(
            "Generates the adversarial test fixture, then feeds its hidden payload "
            "to two simulated agents: one with no protection, one running behind VibeCheck."
        )
        if st.button("▶ Run Live Demo", type="primary"):
            pdf_path = generate_adversarial_pdf()
            parsed = parse_pdf(pdf_path)
            score_result = engine.score(parsed.hidden_text or parsed.full_raw_text, matched_patterns=parsed.matched_patterns)

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("### 🔓 Vulnerable Agent (unprotected)")
                with st.spinner("Simulating naive agent execution..."):
                    result = run_vulnerable_agent_demo(parsed.hidden_text)
                if result["executed"]:
                    st.error(f"❌ HIJACKED: {result['detail']}")
                else:
                    st.warning(result["detail"])

            with col2:
                st.markdown("### 🛡️ VibeCheck AI Protected")
                st.write(f"1. Unmasked hidden text ({parsed.hidden_char_count} chars, {parsed.zero_width_count} zero-width chars)")
                st.write(f"2. Vector threat score: **{score_result.score:.3f}** → **{score_result.verdict}**")
                if score_result.verdict == "CRITICAL":
                    st.error(f"3. Payload stripped. Nearest threat category: {score_result.nearest_category}")
                elif score_result.verdict == "AMBIGUOUS":
                    st.warning(f"3. Routed to human-in-the-loop review. Nearest category: {score_result.nearest_category}")
                else:
                    st.success("3. Content scored safe, forwarded.")

                protected_result = run_protected_agent_demo(parsed.hidden_text)
                if protected_result["blocked"]:
                    st.success(f"4. Circuit breaker: {protected_result['detail']} ({protected_result['latency_ms']:.4f}ms)")
                else:
                    st.info(f"4. Circuit breaker: {protected_result['detail']}")

            st.session_state.stats["docs_scanned"] += 1
            st.session_state.stats["bytes_stripped"] += parsed.hidden_char_count
            log_audit({
                "file": "adversarial_resume.pdf (live demo)",
                "hidden_chars": parsed.hidden_char_count,
                "zero_width": parsed.zero_width_count,
                "score": round(score_result.score, 3),
                "verdict": score_result.verdict,
                "patterns": [k for k, v in parsed.matched_patterns.items() if v],
            })

    # ---------------- Upload & Scan ----------------
    with tab_upload:
        st.subheader("Scan a PDF")
        uploaded = st.file_uploader("Drop a PDF resume / document", type=["pdf"])
        if uploaded is not None:
            tmp_path = f"/tmp/{uploaded.name}"
            with open(tmp_path, "wb") as f:
                f.write(uploaded.getbuffer())

            start = time.perf_counter()
            parsed = parse_pdf(tmp_path)
            score_result = engine.score(parsed.hidden_text or parsed.full_raw_text, matched_patterns=parsed.matched_patterns)
            total_latency_ms = (time.perf_counter() - start) * 1000

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Execution Latency", f"{total_latency_ms:.2f} ms")
            m2.metric("Threat Cosine Similarity", f"{score_result.score:.3f}")
            m3.metric("Blocked Subprocess Calls", st.session_state.stats["blocked_subprocess_calls"])
            m4.metric("Stripped Bytes", parsed.hidden_char_count)

            if score_result.verdict == "CRITICAL":
                st.error(f"🚨 CRITICAL THREAT (score {score_result.score:.3f}) — nearest category: **{score_result.nearest_category}**. Payload quarantined.")
            elif score_result.verdict == "AMBIGUOUS":
                st.warning(f"⚠️ AMBIGUOUS (score {score_result.score:.3f}) — routed to human review. Nearest category: **{score_result.nearest_category}**")
            else:
                st.success(f"✅ SAFE (score {score_result.score:.3f}) — forwarded to downstream LLM.")

            with st.expander("Details"):
                st.write(f"Pages: {parsed.page_count}")
                st.write(f"Hidden/micro-font characters found: {parsed.hidden_char_count}")
                st.write(f"Zero-width characters found: {parsed.zero_width_count}")
                st.write(f"Matched suspicious patterns: {parsed.matched_pattern_names or 'none'}")
                if parsed.hidden_text:
                    st.code(parsed.hidden_text, language="text")
                st.write("Sanitized (visible-only) text forwarded downstream:")
                st.text(parsed.sanitized_text[:2000])

            st.session_state.stats["docs_scanned"] += 1
            st.session_state.stats["bytes_stripped"] += parsed.hidden_char_count
            log_audit({
                "file": uploaded.name,
                "hidden_chars": parsed.hidden_char_count,
                "zero_width": parsed.zero_width_count,
                "score": round(score_result.score, 3),
                "verdict": score_result.verdict,
                "patterns": parsed.matched_pattern_names,
            })

    # ---------------- Audit Log ----------------
    with tab_audit:
        st.subheader("Audit Log")
        st.write(f"Documents scanned: {st.session_state.stats['docs_scanned']} | "
                  f"Subprocess calls blocked: {st.session_state.stats['blocked_subprocess_calls']} | "
                  f"Total bytes stripped: {st.session_state.stats['bytes_stripped']}")
        if not st.session_state.audit_log:
            st.write("No scans yet.")
        for entry in st.session_state.audit_log:
            verdict_color = {"CRITICAL": "🔴", "AMBIGUOUS": "🟡", "SAFE": "🟢"}.get(entry["verdict"], "⚪")
            st.markdown(
                f"<div class='audit-row'>{entry['ts']} {verdict_color} <b>{entry['file']}</b> — "
                f"score={entry['score']} verdict={entry['verdict']} "
                f"hidden_chars={entry['hidden_chars']} zero_width={entry['zero_width']} "
                f"patterns={entry['patterns']}</div>",
                unsafe_allow_html=True,
            )

        if BLOCK_LOG:
            st.subheader("Circuit Breaker Block Log")
            for b in BLOCK_LOG:
                st.markdown(
                    f"<div class='audit-row'>cmd=`{b.command}` pattern=`{b.matched_pattern}` "
                    f"latency={b.latency_ms:.4f}ms</div>",
                    unsafe_allow_html=True,
                )

    # ---------------- BLE Mesh Sync ----------------
    with tab_sync:
        st.subheader("Peer-to-Peer Threat Vector Sync")
        st.write(
            "Exchanges newly confirmed threat exemplars with a nearby VibeCheck peer over BLE, "
            "authenticated with Ed25519 signatures and encrypted with AES-256-GCM over an "
            "X25519 ECDH session key. In this environment BLE transport is simulated (no "
            "physical adapter available), but the cryptography below is real and fully executed."
        )
        if st.button("🔄 Run Secure Sync Demo"):
            new_exemplar = st.session_state.get("last_flagged_text", "New confirmed attack phrase from this session.")
            result = simulate_secure_handshake_and_sync({"session_flagged": [new_exemplar]})
            c1, c2, c3 = st.columns(3)
            c1.metric("Mutual Auth", "✅ OK" if result["mutual_auth_ok"] else "❌ FAILED")
            c2.metric("Key Agreement", "✅ OK" if result["key_agreement_ok"] else "❌ FAILED")
            c3.metric("Integrity Check", "✅ OK" if result["integrity_ok"] else "❌ FAILED")
            st.write(f"Transport: {result['transport']} | Ciphertext size: {result['ciphertext_bytes']} bytes")


if __name__ == "__main__":
    main()
