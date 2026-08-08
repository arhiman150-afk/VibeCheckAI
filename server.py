"""
server.py — VibeCheck AI Virtual Security Server
FastAPI backend providing 24/7 REST endpoints for remote threat scanning.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
import uvicorn
import shutil
import os

from parser import parse_pdf
from vector_engine import ThreatVectorEngine
from circuit_breaker import inspect_command, SecurityException
from url_scanner import scan_remote_url, SSRFSecurityError
from malware_engine import MalwareThreatDetector

app = FastAPI(
    title="VibeCheck AI Virtual Security Server",
    version="2.0",
    description="24/7 Cloud API Guard for Prompt Injections, Malware, and Egress Control"
)

# Initialize engines in Virtual Server RAM
vector_engine = ThreatVectorEngine()
malware_engine = MalwareThreatDetector() if 'MalwareThreatDetector' in globals() else None

class URLScanRequest(BaseModel):
    url: str

class CommandCheckRequest(BaseModel):
    command: str

@app.get("/")
def health_check():
    return {"status": "ONLINE", "server": "VibeCheck AI Virtual Guard", "mode": "24/7 Cloud Active"}

@app.post("/scan/pdf")
async def scan_pdf_endpoint(file: UploadFile = File(...)):
    """Receives remote PDF uploads and scans them in Virtual Server RAM."""
    temp_path = f"/tmp/{file.filename}"
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    parsed = parse_pdf(temp_path)
    score_res = vector_engine.score(parsed.hidden_text or parsed.full_raw_text)
    
    malware_res = {"malware_threat_detected": False, "risk_level": "CLEAN"}
    if malware_engine:
        malware_res = malware_engine.analyze_stream(parsed.full_raw_text)

    os.remove(temp_path)

    return {
        "filename": file.filename,
        "vector_threat_score": score_res.score,
        "verdict": score_res.verdict,
        "hidden_chars_unmasked": parsed.hidden_char_count,
        "zero_width_chars": parsed.zero_width_count,
        "malware_status": malware_res["risk_level"]
    }

@app.post("/scan/url")
def scan_url_endpoint(payload: URLScanRequest):
    """Fetches remote URLs, unmasks hidden HTML injections, and scans content."""
    try:
        url_data = scan_remote_url(payload.url)
        score_res = vector_engine.score(url_data.get("unmasked_hidden") or url_data.get("raw_text_stream", ""))
        
        return {
            "source_url": payload.url,
            "vector_threat_score": score_res.score,
            "verdict": score_res.verdict,
            "hidden_html_tags": url_data.get("comment_count", 0) + url_data.get("hidden_tag_count", 0)
        }
    except SSRFSecurityError as ssrf_err:
        raise HTTPException(status_code=400, detail=str(ssrf_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server fetch failed: {e}")

@app.post("/check/command")
def check_command_endpoint(payload: CommandCheckRequest):
    """Virtual Circuit Breaker endpoint to check outgoing tool execution commands."""
    try:
        # Runs command through regex and subshell de-obfuscation
        inspect_command(payload.command)
        return {"status": "ALLOWED", "command": payload.command}
    except SecurityException as sec_err:
        return {
            "status": "BLOCKED",
            "command": payload.command,
            "reason": str(sec_err.matched_pattern),
            "latency_ms": sec_err.latency_ms
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
  
