"""
tray_app.py — Desktop System Tray Interface
Provides a native OS tray icon to toggle protection and view status.
"""

import pystray
from PIL import Image, ImageDraw
import threading
import sys

# Generate simple tray icon graphics
def create_icon_image(color="green"):
    image = Image.new('RGB', (64, 64), color=color)
    dc = ImageDraw.Draw(image)
    dc.rectangle((16, 16, 48, 48), fill="white")
    return image

is_protection_active = True

def toggle_protection(icon, item):
    global is_protection_active
    is_protection_active = not is_protection_active
    status = "Active" if is_protection_active else "Disabled"
    color = "green" if is_protection_active else "red"
    icon.icon = create_icon_image(color)
    icon.notify(f"VibeCheck AI Protection is now {status}")

def exit_app(icon, item):
    icon.stop()
    sys.exit()

def setup_tray():
    menu = pystray.Menu(
        pystray.MenuItem("VibeCheck AI — Protected", None, enabled=False),
        pystray.MenuItem("Toggle System Guard", toggle_protection),
        pystray.MenuItem("Exit Agent", exit_app)
    )
    icon = pystray.Icon("VibeCheck AI", create_icon_image("green"), "VibeCheck AI Control Plane", menu)
    icon.run()

if __name__ == "__main__":
    setup_tray()
  
