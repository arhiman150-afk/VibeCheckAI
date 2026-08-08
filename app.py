"""
app.py — VibeCheck AI (BrainRot Guard) Command Center

Streamlit UI tying together:
- parser.py (unmasking & PostScript parsing)
- vector_engine.py (threat scoring & dual-threshold model)
- circuit_breaker.py (egress protection & subprocess interceptor)
- ble_mesh.py (peer sync demo & mTLS crypto)
- url_scanner.py (SSRF protection & web unmasking)
- malware_engine.py (virus & worm heuristic analyzer)
"""

from __future__ import annotations

import os
import time
import subprocess
import streamlit as st

# Core project imports
from parser import parse_pdf
from vector_engine import ThreatVectorEngine, USING_FALLBACK, SAFE_THRESHOLD, CRITICAL_THRESHOLD
from circuit_breaker import enable_circuit_breaker, taint_scope, SecurityException, BLOCK_LOG
from ble_mesh import simulate_secure_handshake_and_sync, BLEAK_AVAILABLE
from create_payload import generate_adversarial_pdf

# New module imports with graceful fallbacks
try:
    from url_scanner import scan_remote_url, SSRFSecurityError
except ImportError:
    scan_remote_url = None
    SSRFSecurityError = Exception

try:
    from malware_engine import MalwareThreatDetector
except ImportError:
    MalwareThreatDetector = None


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
    .threat-card-critical {
        background-color: #3C1E1E; border: 1px solid #F85149;
        padding: 14px; border-radius: 6px; color: #FF7B72; margin-bottom: 10px;
    }
    .threat-card-clean {
        background-color: #1C3326; border: 1px solid #3FB950;
        padding: 14px; border-radius: 6px; color: #56D364; margin-bottom: 10px;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_engine():
    return ThreatVectorEngine()


@st.cache_resource
def get_malware_detector():
    if MalwareThreatDetector:
        return MalwareThreatDetector()
    return None


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
    that looks like a tool call."""
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
            return {"executed": True, "detail": f"Agent attempted curl (network call failed/timed out: {e}), but the dangerous call was NOT stopped."}
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
        return {"blocked": True, "detail": "Blocked before OS process spawn.", "latency_ms": e.latency_ms}


def main():
    init_state()
    enable_circuit_breaker()
    engine = get_engine()
    malware_detector = get_malware_detector()

    st.title("🛡️ VibeCheck AI — BrainRot Guard")
    st.caption("Local-first prompt-injection, web unmasking, malware detection & egress protection for AI agents")

    backend_label = "⚠️ Fallback hashed-embedding scorer" if USING_FALLBACK else "✅ sentence-transformers (all-MiniLM-L6-v2) + ChromaDB"
    ble_label = "✅ Real BLE hardware transport available" if BLEAK_AVAILABLE else "⚠️ BLE transport simulated (crypto real)"
    malware_label = "✅ Active Heuristic Analyzer" if malware_detector else "⚠️ Heuristic Module Offline"
    url_label = "✅ Active SSRF Guard & Web Unmasker" if scan_remote_url else "⚠️ Web Scanner Module Offline"

    st.info(
        f"**Vector Backend:** {backend_label} | **BLE Transport:** {ble_label}  \n"
        f"**Malware Engine:** {malware_label} | **URL Scanner:** {url_label}",
        icon="ℹ️"
    )

    tab_live, tab_upload, tab_audit, tab_sync = st.tabs(
        ["🎬 Live Demo Mode", "📄 Upload & Web Scan", "📋 Audit Log", "🔗 BLE Mesh Sync"]
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

    # ---------------- Upload & Web Scan ----------------
    with tab_upload:
        st.subheader("Scan Document or Web Page")
        
        scan_source = st.radio("Select Target Source:", ["📄 Local PDF Document", "🌐 Web Page URL"], horizontal=True)

        if scan_source == "📄 Local PDF Document":
            uploaded = st.file_uploader("Drop a PDF resume / document", type=["pdf"])
            if uploaded is not None:
                tmp_path = f"/tmp/{uploaded.name}"
                with open(tmp_path, "wb") as f:
                    f.write(uploaded.getbuffer())

                start = time.perf_counter()
                parsed = parse_pdf(tmp_path)
                score_result = engine.score(parsed.hidden_text or parsed.full_raw_text, matched_patterns=parsed.matched_patterns)
                
                # Check for virus/worm malware signatures
                malware_res = {"malware_threat_detected": False, "risk_level": "CLEAN", "threat_details": []}
                if malware_detector:
                    malware_res = malware_detector.analyze_stream(parsed.full_raw_text)

                total_latency_ms = (time.perf_counter() - start) * 1000

                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Execution Latency", f"{total_latency_ms:.2f} ms")
                m2.metric("Threat Vector Score", f"{score_result.score:.3f}")
                m3.metric("Malware Status", malware_res["risk_level"])
                m4.metric("Blocked Calls", st.session_state.stats["blocked_subprocess_calls"])
                m5.metric("Stripped Bytes", parsed.hidden_char_count)

                if malware_res["malware_threat_detected"]:
                    st.error("🚨 VIRUS / WORM PAYLOAD SIGNATURE MATCHED IN DOCUMENT STREAM")
                    st.json(malware_res["threat_details"])

                if score_result.verdict == "CRITICAL":
                    st.error(f"🚨 CRITICAL THREAT (score {score_result.score:.3f}) — nearest category: **{score_result.nearest_category}**. Payload quarantined.")
                elif score_result.verdict == "AMBIGUOUS":
                    st.warning(f"⚠️ AMBIGUOUS (score {score_result.score:.3f}) — routed to human review. Nearest category: **{score_result.nearest_category}**")
                else:
                    st.success(f"✅ SAFE (score {score_result.score:.3f}) — forwarded to downstream LLM.")

                with st.expander("Inspection Details"):
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

        elif scan_source == "🌐 Web Page URL":
            target_url = st.text_input("Enter Web URL to analyze:", placeholder="https://example.com/article_with_injection")
            if st.button("Run Web & Threat Analysis"):
                if not scan_remote_url:
                    st.error("URL Scanner module (url_scanner.py) is not available.")
                else:
                    start = time.perf_counter()
                    try:
                        url_res = scan_remote_url(target_url)
                        text_to_score = url_res.get("unmasked_hidden") or url_res.get("raw_text_stream", "")
                        
                        score_result = engine.score(text_to_score)
                        
                        malware_res = {"malware_threat_detected": False, "risk_level": "CLEAN", "threat_details": []}
                        if malware_detector:
                            malware_res = malware_detector.analyze_stream(url_res.get("raw_text_stream", ""))

                        total_latency_ms = (time.perf_counter() - start) * 1000

                        m1, m2, m3, m4 = st.columns(4)
                        m1.metric("Execution Latency", f"{total_latency_ms:.2f} ms")
                        m2.metric("Threat Vector Score", f"{score_result.score:.3f}")
                        m3.metric("Malware Status", malware_res["risk_level"])
                        m4.metric("Hidden HTML Elements", url_res.get("comment_count", 0) + url_res.get("hidden_tag_count", 0))

                        if malware_res["malware_threat_detected"]:
                            st.error("🚨 VIRUS / WORM PAYLOAD SIGNATURE MATCHED IN WEB STREAM")
                            st.json(malware_res["threat_details"])

                        if score_result.verdict == "CRITICAL":
                            st.error(f"🚨 CRITICAL THREAT (score {score_result.score:.3f}) — nearest category: **{score_result.nearest_category}**. Payload quarantined.")
                        elif score_result.verdict == "AMBIGUOUS":
                            st.warning(f"⚠️ AMBIGUOUS (score {score_result.score:.3f}) — routed to human review. Nearest category: **{score_result.nearest_category}**")
                        else:
                            st.success(f"✅ SAFE (score {score_result.score:.3f}) — content verified clean.")

                        with st.expander("Web Inspection Details"):
                            st.write(f"Source URL: {url_res.get('source')}")
                            st.write(f"Content Type: {url_res.get('content_type')}")
                            st.write(f"HTML Comments Found: {url_res.get('comment_count', 0)}")
                            st.write(f"Hidden CSS Tags Found: {url_res.get('hidden_tag_count', 0)}")
                            if url_res.get("unmasked_hidden"):
                                st.write("Unmasked Hidden Payload String:")
                                st.code(url_res["unmasked_hidden"], language="text")
                            st.write("Extracted Raw Text Stream:")
                            st.text(url_res.get("raw_text_stream", "")[:2000])

                        st.session_state.stats["docs_scanned"] += 1
                        log_audit({
                            "file": target_url,
                            "hidden_chars": len(url_res.get("unmasked_hidden", "")),
                            "zero_width": 0,
                            "score": round(score_result.score, 3),
                            "verdict": score_result.verdict,
                            "patterns": ["Web Hidden HTML/CSS Injection"] if url_res.get("unmasked_hidden") else [],
                        })

                    except SSRFSecurityError as ssrf_err:
                        st.error(f"🚨 SSRF SECURITY ALERT: {ssrf_err}")
                    except Exception as err:
                        st.error(f"Failed to scan URL: {err}")

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
                    
