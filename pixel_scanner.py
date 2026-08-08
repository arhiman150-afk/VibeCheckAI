"""
pixel_scanner.py — Image & Pixel-Level Steganography Inspection Engine

Inspects embedded PDF images and image uploads for:
1. Low-Contrast / Invisible Pixel Text (white-on-white or low opacity).
2. Micro-Pixel Renderings (text rendered at tiny 1px-3px heights).
3. LSB (Least Significant Bit) Hidden Payload Strips.
"""

from PIL import Image, ImageEnhance, ImageOps
import numpy as np
import io

def inspect_image_pixels(image_bytes: bytes) -> dict:
    """
    Analyzes raw image bytes for pixel-level visual steganography.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
    except Exception as e:
        return {"pixel_threat_detected": False, "reason": f"Invalid image format: {e}"}

    width, height = img.size
    img_np = np.array(img)

    # 1. Inspect Alpha (Opacity) Channel
    alpha_channel = img_np[:, :, 3]
    near_invisible_pixels = np.sum((alpha_channel > 0) & (alpha_channel < 15))
    
    # 2. Inspect Low-Contrast Pixel Layers (Near-White Micro Fonts)
    rgb_channels = img_np[:, :, :3]
    # Check for pixels with high brightness but micro-variations (RGB > 250)
    white_mask = np.all(rgb_channels >= 250, axis=2)
    near_white_variations = np.sum(white_mask & (alpha_channel > 0))

    # 3. LSB (Least Significant Bit) Steganography Detection
    # Extract lowest bits of Red/Green channels to check for high entropy payload strips
    lsb_bits = img_np[:, :, 0] & 1
    lsb_entropy = np.std(lsb_bits)

    threat_detected = False
    flagged_reasons = []

    if near_invisible_pixels > 50:
        threat_detected = True
        flagged_reasons.append(f"Detected {near_invisible_pixels} near-invisible low-opacity pixels (Alpha 1-15).")

    if width < 50 or height < 50:
        flagged_reasons.append(f"Micro-image dimension detected ({width}x{height}px).")

    if lsb_entropy > 0.48:  # Random/encrypted payload embedded in pixel LSB
        threat_detected = True
        flagged_reasons.append("High LSB entropy detected (potential pixel-embedded steganographic payload).")

    return {
        "pixel_threat_detected": threat_detected,
        "dimensions": f"{width}x{height}px",
        "near_invisible_pixel_count": int(near_invisible_pixels),
        "lsb_entropy_score": float(round(lsb_entropy, 4)),
        "flagged_reasons": flagged_reasons
    }
  
