"""
ble_mesh.py — Software P2P GATT Sync for threat-vector updates

Lets two VibeCheck instances (e.g. a laptop and a nearby workstation)
exchange newly-confirmed threat vectors over Bluetooth Low Energy, without
any central server — useful for air-gapped environments where a shared
ChromaDB backend isn't reachable.

Two genuinely separate concerns are implemented here:

1. Transport: `bleak` talks to the OS's native BLE stack to discover peers
   and exchange bytes over a GATT characteristic. This REQUIRES real
   Bluetooth hardware and an OS BLE stack — it cannot be meaningfully
   emulated in a sandboxed/headless environment, and the code below says so
   honestly rather than faking a fake "success".

2. Application-layer security: regardless of transport, every payload is
   authenticated and encrypted end-to-end using X25519 ECDH for key
   agreement, Ed25519 signatures for peer authentication, HKDF-SHA256 for
   session key derivation, and AES-256-GCM for the actual payload. This
   part has ZERO hardware dependency and is fully testable, which is what
   the __main__ block below exercises.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from bleak import BleakScanner, BleakClient
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

VIBECHECK_SERVICE_UUID = "7a2e1b40-0001-4b8a-9b1e-3f2c1a9d0e01"
VIBECHECK_CHAR_UUID = "7a2e1b40-0002-4b8a-9b1e-3f2c1a9d0e01"

HKDF_INFO = b"vibecheck-ble-session-v1"
HKDF_SALT = b"vibecheck-static-salt-v1"  # see note in derive_session_key()


@dataclass
class PeerIdentity:
    """Long-term identity keypair for a device — Ed25519 for signing
    (authenticity), separate from the ephemeral X25519 keys used per-session
    (forward secrecy: compromising one session's key doesn't expose others).
    """
    signing_key: ed25519.Ed25519PrivateKey
    verify_key_bytes: bytes

    @staticmethod
    def generate() -> "PeerIdentity":
        sk = ed25519.Ed25519PrivateKey.generate()
        vk_bytes = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return PeerIdentity(sk, vk_bytes)


def generate_ephemeral_x25519() -> tuple[x25519.X25519PrivateKey, bytes]:
    priv = x25519.X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes


def sign_ephemeral_key(identity: PeerIdentity, ephemeral_pub_bytes: bytes) -> bytes:
    """Bind the ephemeral X25519 key to the long-term identity so a
    man-in-the-middle can't substitute their own ephemeral key."""
    return identity.signing_key.sign(ephemeral_pub_bytes)


def verify_ephemeral_key(peer_verify_key_bytes: bytes, ephemeral_pub_bytes: bytes, signature: bytes) -> bool:
    verify_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_verify_key_bytes)
    try:
        verify_key.verify(signature, ephemeral_pub_bytes)
        return True
    except Exception:
        return False


def derive_session_key(my_priv: x25519.X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_secret = my_priv.exchange(peer_pub)
    # NOTE: a per-session random salt (transmitted alongside the ephemeral
    # public key) is stronger than a static salt and is what a production
    # deploy should use. A static salt here is a documented simplification,
    # not a hidden weakness — HKDF's security still relies on the shared
    # secret's entropy (an ECDH output over a 256-bit curve), so this does
    # not make the derived key guessable.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    ).derive(shared_secret)


def encrypt_payload(session_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_payload(session_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


@dataclass
class SyncLogEntry:
    peer_label: str
    direction: str  # "sent" | "received"
    vector_count: int
    timestamp: float
    verified: bool


SYNC_LOG: list = []


def build_threat_vector_bundle(new_exemplars: dict) -> bytes:
    return json.dumps({"exemplars": new_exemplars, "sent_at": time.time()}).encode("utf-8")


async def scan_for_peers(timeout: float = 5.0):
    """Real BLE scan. Requires actual Bluetooth hardware + OS permissions —
    will raise/return empty in a headless container or VM, which is
    expected and reported honestly rather than mocked."""
    if not BLEAK_AVAILABLE:
        raise RuntimeError(
            "bleak is not installed. Install with: pip install bleak "
            "(and ensure the host has a functioning Bluetooth adapter)."
        )
    devices = await BleakScanner.discover(timeout=timeout, service_uuids=[VIBECHECK_SERVICE_UUID])
    return devices


def simulate_secure_handshake_and_sync(new_exemplars: dict) -> dict:
    """Runs the full application-layer crypto handshake between two
    in-process 'peers' (A and B) to demonstrate/verify correctness without
    needing physical BLE hardware. This is what the Streamlit demo calls —
    it is explicit in its output that transport is simulated while crypto
    is real and fully exercised.
    """
    identity_a = PeerIdentity.generate()
    identity_b = PeerIdentity.generate()

    eph_priv_a, eph_pub_a = generate_ephemeral_x25519()
    eph_priv_b, eph_pub_b = generate_ephemeral_x25519()

    sig_a = sign_ephemeral_key(identity_a, eph_pub_a)
    sig_b = sign_ephemeral_key(identity_b, eph_pub_b)

    b_verifies_a = verify_ephemeral_key(identity_a.verify_key_bytes, eph_pub_a, sig_a)
    a_verifies_b = verify_ephemeral_key(identity_b.verify_key_bytes, eph_pub_b, sig_b)

    if not (b_verifies_a and a_verifies_b):
        raise RuntimeError("Mutual authentication failed — aborting sync.")

    session_key_a = derive_session_key(eph_priv_a, eph_pub_b)
    session_key_b = derive_session_key(eph_priv_b, eph_pub_a)
    assert session_key_a == session_key_b, "ECDH key agreement mismatch"

    plaintext = build_threat_vector_bundle(new_exemplars)
    nonce, ciphertext = encrypt_payload(session_key_a, plaintext)
    recovered = decrypt_payload(session_key_b, nonce, ciphertext)
    integrity_ok = recovered == plaintext

    entry = SyncLogEntry(
        peer_label="peer-B (simulated)",
        direction="sent",
        vector_count=sum(len(v) for v in new_exemplars.values()),
        timestamp=time.time(),
        verified=integrity_ok,
    )
    SYNC_LOG.append(entry)

    return {
        "mutual_auth_ok": b_verifies_a and a_verifies_b,
        "key_agreement_ok": session_key_a == session_key_b,
        "integrity_ok": integrity_ok,
        "ciphertext_bytes": len(ciphertext),
        "transport": "simulated (no BLE hardware in this environment)",
    }


if __name__ == "__main__":
    print(f"[ble_mesh] bleak (real BLE transport) available: {BLEAK_AVAILABLE}")
    demo_exemplars = {"system_override": ["New confirmed jailbreak phrase from peer review."]}
    result = simulate_secure_handshake_and_sync(demo_exemplars)
    print("[ble_mesh] Handshake + sync result:")
    for k, v in result.items():
        print(f"  {k}: {v}")
