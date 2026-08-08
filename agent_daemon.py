"""
agent_daemon.py — Background Security Service
Monitors the Downloads folder in real-time, scanning new files automatically.
"""

import time
import os
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Import your existing pipeline engines
from parser import parse_pdf
from vector_engine import ThreatVectorEngine
from malware_engine import MalwareThreatDetector

vector_engine = ThreatVectorEngine()
malware_engine = MalwareThreatDetector() if 'MalwareThreatDetector' in globals() else None

class SystemInboundGuardHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        if file_path.endswith('.pdf'):
            print(f"[INBOUND GUARD] New file detected on OS: {file_path}")
            
            # Allow file to finish writing
            time.sleep(0.5)
            
            # Run background inspection
            parsed = parse_pdf(file_path)
            score_res = vector_engine.score(parsed.hidden_text or parsed.full_raw_text)
            
            if score_res.verdict == "CRITICAL":
                print(f"[ALERT] CRITICAL THREAT DETECTED ({score_res.score:.2f})!")
                print(f"[ACTION] Quarantining file: {file_path}")
                quarantine_path = file_path + ".quarantine"
                os.rename(file_path, quarantine_path)
            else:
                print(f"[CLEAN] File verified safe: {file_path}")

def start_daemon():
    downloads_path = str(Path.home() / "Downloads")
    event_handler = SystemInboundGuardHandler()
    observer = Observer()
    observer.schedule(event_handler, path=downloads_path, recursive=False)
    observer.start()
    print(f"🛡️ VibeCheck AI Background Daemon running. Watching: {downloads_path}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_daemon()
  
