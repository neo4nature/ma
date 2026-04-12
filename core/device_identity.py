from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization


@dataclass
class DeviceIdentity:
    ok: bool
    fingerprint: str | None = None
    device_pub_pem: str | None = None
    transport: str | None = None
    device_label: str | None = None
    error: str | None = None


def verify_device_hello(resp: dict) -> DeviceIdentity:
    """Verify walletd/device attestation.

    walletd returns:
      - device_pub_b64 (PEM bytes base64)
      - fingerprint
      - attestation_msg (utf-8 string)
      - attestation_sig_b64

    We verify Ed25519 signature over attestation_msg.

    Security note (v0.x): this is *self-signed* attestation.
    Trust is established by *pinning* (storing) the first seen
    device fingerprint / pubkey per user, and treating changes as suspicious.
    """
    try:
        pub_pem_bytes = base64.b64decode((resp.get("device_pub_b64") or "").encode("ascii"))
        pub_pem = pub_pem_bytes.decode("utf-8", errors="ignore")
        fp = (resp.get("fingerprint") or "").strip()
        msg = (resp.get("attestation_msg") or "").encode("utf-8")
        sig = base64.b64decode((resp.get("attestation_sig_b64") or "").encode("ascii"))

        pub = serialization.load_pem_public_key(pub_pem_bytes)
        pub.verify(sig, msg)

        return DeviceIdentity(
            ok=True,
            fingerprint=fp,
            device_pub_pem=pub_pem,
            transport=(resp.get("transport") or "").strip(),
            device_label=(resp.get("device") or "").strip(),
        )
    except Exception as e:
        return DeviceIdentity(
            ok=False,
            fingerprint=(resp.get("fingerprint") or None),
            transport=(resp.get("transport") or None),
            device_label=(resp.get("device") or None),
            error=e.__class__.__name__,
        )
