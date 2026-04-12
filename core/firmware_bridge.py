"""core/firmware_bridge.py

Przełącznik SIGNER_MODE=FIRMWARE.

v0.4: INPROC (symulacja portfela w tym samym procesie Flask)
v0.5: SOCKET (podpis poza Flask przez daemon walletd)
v0.6: SERIAL (PTY framing) – transport zbliżony do USB CDC/UART.

Cel: logika aplikacji się nie zmienia, zmienia się tylko TRANSPORT.
"""
from __future__ import annotations

from typing import Any, Dict

import os
import socket
import struct

import base64
import zlib
import time

from core.host_protocol import (
    encode_sign_request,
    encode_sign_hash_request,
    decode_sign_response,
    encode_device_hello_request,
    decode_device_hello_response,
)
from wallet.tx_signer import sign_transaction


def _simulated_firmware_handle(raw: bytes) -> bytes:
    """Simulated firmware handler.

    Supports:
    - DEVICE_HELLO (v1)
    - SIGN_TX (v2): signs canonical tx JSON
    - SIGN (v2): signs a payload hash with an explicit purpose
    """
    import json
    from wallet.tx_signer import sign_transaction, sign_hash

    req = json.loads(raw.decode("utf-8"))

    # ENFORCE_V2_SIGN: signature requests must be v>=2
    if req.get("type") in ("SIGN", "SIGN_TX"):
        if int(req.get("v") or 1) < 2:
            return json.dumps({"type":"ERROR","v":2,"status":"REJECTED","error":"sign_requires_v2"}).encode("utf-8")

    if req.get("type") == "DEVICE_HELLO":
        # In-proc mock identity (not persisted)
        pub = "MOCK_DEVICE_PUB"
        fp = "MA-MOCK-0000-0000"
        resp = {
            "type": "DEVICE_HELLO_RESP",
            "v": 1,
            "status": "OK",
            "device_pub_b64": pub,
            "fingerprint": fp,
            "attestation_msg": "mock",
            "attestation_sig_b64": "",
            "transport": "MOCK_PROTO",
            "device": "MA_WALLET_SIM",
        }
        return json.dumps(resp, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # New generic signer
    if req.get("type") == "SIGN":
        sender = req.get("sender") or ""
        purpose = (req.get("purpose") or "GENERIC").strip().upper()
        payload_hash_b64 = req.get("payload_hash_b64") or ""
        sig_b64 = sign_hash(payload_hash_b64, signer=sender, purpose=purpose)
        resp = {
            "type": "SIGN_RESP",
            "v": 2,
            "status": "OK",
            "transport": "MOCK_PROTO",
            "device": "MA_WALLET_SIM",
            "purpose": purpose,
            "sig_b64": sig_b64,
        }
        return json.dumps(resp, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Legacy tx signing
    if req.get("type") != "SIGN_TX":
        return json.dumps({"type": "ERROR", "error": "unsupported"}).encode("utf-8")

    sender = req["sender"]
    tx = req["tx"]
    sig_b64 = sign_transaction(tx, signer=sender)

    resp = {
        "type": "SIGN_TX_RESP",
        "v": 1,
        "status": "OK",
        "transport": "MOCK_PROTO",
        "device": "MA_WALLET_SIM",
        "tx_sig_b64": sig_b64,
    }
    return json.dumps(resp, sort_keys=True, separators=(",", ":")).encode("utf-8")
# -------------------------
# SERIAL helpers (PTY framing)
# -------------------------
def _read_exact(fd: int, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            raise EOFError("tty_closed")
        buf += chunk
    return buf


def _read_frame(fd: int, max_len: int = 2_000_000) -> bytes:
    # v0.7 framing: [len:4][crc32:4][payload]
    hdr = _read_exact(fd, 8)
    ln, crc = struct.unpack(">II", hdr)
    if ln <= 0 or ln > max_len:
        raise ValueError(f"bad_len:{ln}")
    payload = _read_exact(fd, ln)
    calc = zlib.crc32(payload) & 0xFFFFFFFF
    if calc != crc:
        raise ValueError("bad_crc")
    return payload


def _write_frame(fd: int, payload: bytes) -> None:
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    os.write(fd, struct.pack(">II", len(payload), crc) + payload)


def _serial_exchange(port_path: str, req: bytes, *, timeout_s: float) -> bytes:
    """Exchange a single framed request/response over SERIAL transport.

    Fail fast on protocol errors like bad length/CRC instead of looping until
    timeout. Retry only on transient empty/closed reads until timeout budget is
    exhausted.
    """
    fd = os.open(port_path, os.O_RDWR | os.O_NOCTTY)
    try:
        _write_frame(fd, req)
        start = time.monotonic()
        last_exc: Exception | None = None
        while True:
            try:
                return _read_frame(fd)
            except ValueError:
                raise
            except Exception as exc:
                last_exc = exc
                if time.monotonic() - start > timeout_s:
                    raise TimeoutError("serial_timeout") from last_exc
    finally:
        try:
            os.close(fd)
        except Exception:
            pass


def sign_transaction_via_firmware(tx: Dict[str, Any], sender: str, meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    # In firmware mode, default transport is SERIAL in v0.6 (more hardware-like).
    default_transport = "SERIAL" if os.getenv("MA_SIGNER_MODE", "").strip().upper() == "FIRMWARE" else "INPROC"
    transport = os.getenv("MA_SIGNER_TRANSPORT", default_transport).strip().upper()
    # Meta supports replay-guard fields: counter + nonce
    req = encode_sign_request(tx, sender, meta=meta)

    if transport == "SOCKET":
        host = os.getenv("MA_WALLETD_HOST", "127.0.0.1").strip()
        port = int(os.getenv("MA_WALLETD_PORT", "7788").strip())
        timeout = float(os.getenv("MA_WALLETD_TIMEOUT", "2.0").strip())

        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(req + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        resp_raw = buf.strip() or b"{}"
        resp = decode_sign_response(resp_raw)
        resp["transport"] = "SOCKET"
        resp["device"] = resp.get("device") or "MA_WALLET_DAEMON"
        return resp

    if transport == "SERIAL":
        # Client opens the PTY exposed by walletd and exchanges framed packets.
        port_path = os.getenv("MA_SERIAL_PORT", "runtime/ttyMA0").strip()
        timeout_s = float(os.getenv("MA_SERIAL_TIMEOUT", "2.0").strip())

        # Open as raw binary; PTY behaves like a tty device.
        resp_raw = _serial_exchange(port_path, req, timeout_s=timeout_s)
        resp = decode_sign_response(resp_raw)
        resp["transport"] = "SERIAL"
        resp["device"] = resp.get("device") or "MA_WALLET_PTY"
        return resp

    # Default: INPROC simulation
    resp_raw = _simulated_firmware_handle(req)
    resp = decode_sign_response(resp_raw)
    return resp




def sign_hash_via_firmware(purpose: str, payload_hash_b64: str, sender: str, meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Ask the firmware/daemon to sign a payload hash for a given purpose."""
    default_transport = "SERIAL" if os.getenv("MA_SIGNER_MODE", "").strip().upper() == "FIRMWARE" else "INPROC"
    transport = os.getenv("MA_SIGNER_TRANSPORT", default_transport).strip().upper()
    req = encode_sign_hash_request(purpose, payload_hash_b64, sender, meta=meta)

    if transport == "SOCKET":
        host = os.getenv("MA_WALLETD_HOST", "127.0.0.1").strip()
        port = int(os.getenv("MA_WALLETD_PORT", "7788").strip())
        timeout = float(os.getenv("MA_WALLETD_TIMEOUT", "2.0").strip())
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(req + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        resp_raw = buf.strip() or b"{}"
        resp = decode_sign_response(resp_raw)
        resp["transport"] = "SOCKET"
        resp["device"] = resp.get("device") or "MA_WALLET_DAEMON"
        return resp

    if transport == "SERIAL":
        port_path = os.getenv("MA_SERIAL_PORT", "runtime/ttyMA0").strip()
        timeout_s = float(os.getenv("MA_SERIAL_TIMEOUT", "2.0").strip())
        resp_raw = _serial_exchange(port_path, req, timeout_s=timeout_s)
        resp = decode_sign_response(resp_raw)
        resp["transport"] = "SERIAL"
        resp["device"] = resp.get("device") or "MA_WALLET_PTY"
        return resp

    # INPROC simulation
    resp_raw = _simulated_firmware_handle(req)
    return decode_sign_response(resp_raw)

def device_hello_via_firmware() -> Dict[str, Any]:
    """Query the (simulated) device identity over the selected transport."""
    default_transport = "SERIAL" if os.getenv("MA_SIGNER_MODE", "").strip().upper() == "FIRMWARE" else "INPROC"
    transport = os.getenv("MA_SIGNER_TRANSPORT", default_transport).strip().upper()
    req = encode_device_hello_request()

    if transport == "SOCKET":
        host = os.getenv("MA_WALLETD_HOST", "127.0.0.1").strip()
        port = int(os.getenv("MA_WALLETD_PORT", "7788").strip())
        timeout = float(os.getenv("MA_WALLETD_TIMEOUT", "2.0").strip())

        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(req + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        resp_raw = buf.strip() or b"{}"
        resp = decode_device_hello_response(resp_raw)
        resp["transport"] = "SOCKET"
        return resp

    if transport == "SERIAL":
        port_path = os.getenv("MA_SERIAL_PORT", "runtime/ttyMA0").strip()
        timeout_s = float(os.getenv("MA_SERIAL_TIMEOUT", "2.0").strip())
        fd = os.open(port_path, os.O_RDWR | os.O_NOCTTY)
        try:
            _write_frame(fd, req)
            start = time.monotonic()
            while True:
                try:
                    resp_raw = _read_frame(fd)
                    break
                except Exception:
                    now = time.monotonic()
                    if now - start > timeout_s:
                        raise TimeoutError("serial_timeout")
            resp = decode_device_hello_response(resp_raw)
            resp["transport"] = "SERIAL"
            return resp
        finally:
            try:
                os.close(fd)
            except Exception:
                pass

    # INPROC: ask simulated firmware directly
    resp_raw = _simulated_firmware_handle(req)
    # Simulated firmware doesn't support this; return a minimal placeholder
    try:
        return decode_device_hello_response(resp_raw)
    except Exception:
        return {
            "type": "DEVICE_HELLO_RESP",
            "v": 1,
            "device": "MA_WALLET_SIM",
            "fingerprint": "SIM-DEVICE",
            "device_pub_b64": "",
            "attestation_sig_b64": "",
            "attestation_msg": "",
            "transport": "INPROC",
        }
