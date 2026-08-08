import io
import re
import ipaddress
import urllib.parse
import requests
from bs4 import BeautifulSoup, Comment
import pdfplumber

class SSRFSecurityError(Exception):
    """Raised when an input URL targets an internal or private network IP."""
    pass

def validate_url_safety(url: str) -> str:
    """Blocks loopback, private RFC-1918 networks, and cloud metadata endpoints."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFSecurityError(f"Unsupported protocol scheme: {parsed.scheme}")
    
    hostname = parsed.hostname
    if not hostname:
        raise SSRFSecurityError("Invalid URL hostname.")

    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise SSRFSecurityError(f"[SSRF BLOCKED] Internal network IP target restricted: {ip}")
    except ValueError:
        # Domain name target (e.g. example.com)
        pass

    return url

def scan_remote_url(url: str) -> dict:
    """Fetches URL, unmasking hidden HTML prompt injections and remote PDFs."""
    safe_url = validate_url_safety(url)
    
    headers = {"User-Agent": "VibeCheck-Security-Scanner/2.0"}
    response = requests.get(safe_url, timeout=4.0, headers=headers, stream=True)
    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "").lower()

    # Handling remote PDF documents
    if "application/pdf" in content_type or safe_url.endswith(".pdf"):
        pdf_bytes = io.BytesIO(response.content)
        with pdfplumber.open(pdf_bytes) as pdf:
            extracted_pages = [page.extract_text() or "" for page in pdf.pages[:5]]
            raw_text = "\n".join(extracted_pages)
        return {
            "content_type": "pdf",
            "source": safe_url,
            "raw_text_stream": raw_text,
            "unmasked_hidden": ""
        }

    # Handling web HTML pages
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Extract HTML comments where hidden prompt injections reside
    html_comments = [c.string.strip() for c in soup.find_all(text=lambda t: isinstance(t, Comment)) if c.string]
    
    # Extract hidden CSS elements (display:none, visibility:hidden, zero opacity)
    hidden_elements = []
    for tag in soup.find_all(True):
        style = tag.get("style", "").lower().replace(" ", "")
        if "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
            hidden_elements.append(tag.get_text(strip=True))

    visible_text = soup.get_text(separator=" ", strip=True)
    unmasked_hidden_payload = " ".join(html_comments + hidden_elements)
    full_text_stream = f"{unmasked_hidden_payload} {visible_text}".strip()

    return {
        "content_type": "html",
        "source": safe_url,
        "raw_text_stream": full_text_stream,
        "unmasked_hidden": unmasked_hidden_payload,
        "comment_count": len(html_comments),
        "hidden_tag_count": len(hidden_elements)
    }
  
