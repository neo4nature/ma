#!/usr/bin/env python3
"""walletd – local signing daemon (v0.6)

Goal:
- Run the "firmware signer" outside the Flask process.
- Provide a transport that looks like real hardware: SERIAL framing over a TTY.
- Keep the same canonical JSON request/response as core/host_protocol.py.

Modes:
1) SERIAL (default in v0.6 for MA_SIGNER_MODE=FIRMWARE):
   - walletd creates a PTY (pseudo-tty) and exposes a symlink (default: runtime/ttyMA0).
   - Client opens that TTY and exchanges framed packets:
        [4-byte big-endian length][JSON bytes]
2) TCP (legacy / optional, v0.5 style):
   - One request per connection, JSON line delimited.

Env:
- MA_WALLETD_MODE: SERIAL | TCP  (default SERIAL)
- MA_TTY_PATH: path for the PTY symlink (default: runtime/ttyMA0)
- MA_WALLETD_HOST / MA_WALLETD_PORT: for TCP mode (default 127.0.0.1:7788)

Notes:
- We do NOT try to create /dev/ttyMA0 (requires sudo). We expose a safe local path.
- This is a bridge step: later we replace PTY with USB CDC/UART without changing protocol.
"""
from __future__ import annotations

import json
import os
import socketserver
import struct
import zlib
import time
from typing import Any, Dict

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

try:
    import pty
except Exception:  # pragma: no cover
    pty = None  # type: ignore

from core.host_protocol import decode_sign_response  # noqa: F401
from core.firmware_bridge import _simulated_firmware_handle


def _chmod_600(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _ensure_device_keypair(keys_dir: str) -> tuple[ed25519.Ed25519PrivateKey, str, str]:
    """Create/load a persistent device Ed25519 keypair.

    Stored under runtime/ by default so walletd ("device") keeps a stable identity
    across restarts.
    """
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "device_ed25519_priv.pem")
    pub_path = os.path.join(keys_dir, "device_ed25519_pub.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        priv_pem = open(priv_path, "rb").read()
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        pub_pem = open(pub_path, "rb").read()
        pub_b64 = base64.b64encode(pub_pem).decode("ascii")
        fp = _fingerprint_from_pub_pem(pub_pem)
        return priv, pub_b64, fp

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    _chmod_600(priv_path)
    pub_b64 = base64.b64encode(pub_pem).decode("ascii")
    fp = _fingerprint_from_pub_pem(pub_pem)
    return priv, pub_b64, fp


def _fingerprint_from_pub_pem(pub_pem: bytes) -> str:
    h = hashlib.sha256(pub_pem).hexdigest().upper()
    # Make it human-friendly (stable): MA-HW-XXXX-YYYY
    return f"MA-HW-{h[:4]}-{h[4:8]}"


def _make_device_hello(priv: ed25519.Ed25519PrivateKey, pub_b64: str, fp: str, req_id: str) -> Dict[str, Any]:
    msg = f"DEVICE_HELLO|{fp}|{req_id}".encode("utf-8")
    sig = priv.sign(msg)
    return {
        "type": "DEVICE_HELLO_RESP",
        "v": 1,
        "status": "OK",
        "device_pub_b64": pub_b64,
        "fingerprint": fp,
        "attestation_msg": msg.decode("utf-8"),
        "attestation_sig_b64": base64.b64encode(sig).decode("ascii"),
    }


# -------------------------
# TCP (legacy) handler
# -------------------------
class WalletdHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw_line = self.rfile.readline(2_000_000)
        if not raw_line:
            return
        raw_line = raw_line.strip()

        try:
            req = json.loads(raw_line.decode("utf-8"))
            if not isinstance(req, dict):
                raise ValueError("request must be object")
        except Exception as e:
            resp = {"type": "ERROR", "error": f"bad_json:{e.__class__.__name__}"}
            self.wfile.write((json.dumps(resp) + "\n").encode("utf-8"))
            return

        canonical = json.dumps(req, sort_keys=True, separators=(",", ":")).encode("utf-8")

        try:
            # Device identity
            if req.get("type") == "DEVICE_HELLO":
                keys_dir = os.getenv("MA_DEVICE_KEYS_DIR", "runtime/device_keys").strip()
                priv, pub_b64, fp = _ensure_device_keypair(keys_dir)
                resp_obj = _make_device_hello(priv, pub_b64, fp, str(req.get("req_id") or ""))
            else:
                resp_raw = _simulated_firmware_handle(canonical)
                resp_obj = json.loads(resp_raw.decode("utf-8"))
            if isinstance(resp_obj, dict):
                resp_obj.setdefault("transport", "SOCKET")
                resp_obj.setdefault("device", "MA_WALLET_DAEMON")
            out = json.dumps(resp_obj, sort_keys=True, separators=(",", ":"))
        except Exception as e:
            out = json.dumps({"type": "ERROR", "error": f"intern...{e.__class__.__name__}"}, sort_keys=True, separators=(",", ":"))

        self.wfile.write((out + "\n").encode("utf-8"))


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


# -------------------------
# SERIAL (PTY) framing
# -------------------------
def _read_exact(fd: int, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            raise EOFError("tty closed")
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


def _load_replay(path: str) -> Dict[str, Any]:
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
                if isinstance(obj, dict):
                    obj.setdefault("last_counter", {})
                    obj.setdefault("seen", {})
                    return obj
    except Exception:
        pass
    return {"last_counter": {}, "seen": {}}




def _prune_seen_map(seen: Dict[str, Any], ttl_seconds: int, max_items: int = 5000, drop_to: int = 4000) -> Dict[str, Any]:
    now = time.time()
    pruned = {}
    for k, ts in seen.items():
        try:
            if (now - float(ts)) <= ttl_seconds:
                pruned[k] = float(ts)
        except Exception:
            continue
    if len(pruned) > max_items:
        items = sorted(pruned.items(), key=lambda kv: kv[1], reverse=True)
        pruned = dict(items[:drop_to])
    return pruned


def _validate_and_update_replay_guard(req_obj: Dict[str, Any], replay: Dict[str, Any], *, ttl_seconds: int = 86400) -> Dict[str, Any]:
    """Validate v2 replay fields and update replay state.

    Rules:
    - SIGN / SIGN_TX with v>=2 require non-empty sender
    - counter must be positive integer
    - nonce_b64 must be present
    - counter must increase strictly per sender
    - sender:counter:nonce tuple may not repeat
    """
    if req_obj.get("type") not in ("SIGN", "SIGN_TX") or int(req_obj.get("v") or 1) < 2:
        return replay

    sender = (req_obj.get("sender") or "").strip()
    if not sender:
        raise ValueError("sender_required")

    try:
        counter = int(req_obj.get("counter") or 0)
    except Exception as e:
        raise ValueError("bad_counter") from e
    if counter <= 0:
        raise ValueError("counter_required")

    nonce_b64 = (req_obj.get("nonce_b64") or "").strip()
    if not nonce_b64:
        raise ValueError("nonce_required")

    replay.setdefault("last_counter", {})
    replay.setdefault("seen", {})
    replay["seen"] = _prune_seen_map(replay.get("seen", {}), ttl_seconds)

    last = int(replay.get("last_counter", {}).get(sender, -1))
    if counter <= last:
        raise ValueError("replay_counter")

    sk = f"{sender}:{counter}:{nonce_b64}"
    if sk in replay.get("seen", {}):
        raise ValueError("replay_nonce")

    replay["last_counter"][sender] = counter
    replay["seen"][sk] = time.time()
    return replay
def _save_replay(path: str, data: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        # Best-effort only
        pass


def run_serial() -> None:
    if pty is None:
        raise RuntimeError("pty_unavailable")

    tty_link = os.getenv("MA_TTY_PATH", "runtime/ttyMA0").strip()
    runtime_dir = os.path.dirname(tty_link) or "."
    os.makedirs(runtime_dir, exist_ok=True)

    master_fd, slave_fd = pty.openpty()
    slave_name = os.ttyname(slave_fd)

    # Create/replace symlink
    try:
        if os.path.islink(tty_link) or os.path.exists(tty_link):
            os.unlink(tty_link)
        os.symlink(slave_name, tty_link)
    except Exception:
        # If symlink fails (filesystem), fall back to printing the slave name.
        tty_link = slave_name

    print(f"walletd SERIAL ready: {tty_link} -> {slave_name}", flush=True)

    # Replay guard state (best-effort persistence)
    replay_path = os.getenv("MA_REPLAY_FILE", "runtime/replay_guard.json").strip()
    replay = _load_replay(replay_path)

    # Main loop: one frame request -> one frame response
    while True:
        try:
            req_raw = _read_frame(master_fd)
        except EOFError:
            time.sleep(0.05)
            continue
        except Exception as e:
            err = json.dumps({"type": "ERROR", "error": f"rx:{e.__class__.__name__}"}, sort_keys=True, separators=(",", ":")).encode("utf-8")
            try:
                _write_frame(master_fd, err)
            except Exception:
                pass
            continue

        try:
            req_obj = json.loads(req_raw.decode("utf-8"))
            if not isinstance(req_obj, dict):
                raise ValueError("request must be object")

            # Device identity request (no replay guard needed)
            if req_obj.get("type") == "DEVICE_HELLO":
                keys_dir = os.getenv("MA_DEVICE_KEYS_DIR", "runtime/device_keys").strip()
                priv, pub_b64, fp = _ensure_device_keypair(keys_dir)
                resp_obj = _make_device_hello(priv, pub_b64, fp, str(req_obj.get("req_id") or ""))
                resp_obj.setdefault("transport", "SERIAL")
                resp_obj.setdefault("device", "MA_WALLET_PTY")
                out = json.dumps(resp_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
                _write_frame(master_fd, out)
                continue

            # Enforce v2+ for signature requests
            if req_obj.get("type") in ("SIGN","SIGN_TX") and int(req_obj.get("v") or 1) < 2:
                out = json.dumps({"type":"ERROR","v":2,"status":"REJECTED","error":"sign_requires_v2"}).encode("utf-8")
                _write_frame(master_fd, out)
                continue

            # Replay guard for v2 signing requests
            ttl_seconds = int(os.getenv("MA_REPLAY_TTL_SECONDS", "86400").strip())
            replay = _validate_and_update_replay_guard(req_obj, replay, ttl_seconds=ttl_seconds)
            if req_obj.get("type") in ("SIGN", "SIGN_TX") and int(req_obj.get("v") or 1) >= 2:
                _save_replay(replay_path, replay)

            canonical = json.dumps(req_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            resp_raw = _simulated_firmware_handle(canonical)
            resp_obj = json.loads(resp_raw.decode("utf-8"))
            if isinstance(resp_obj, dict):
                resp_obj.setdefault("transport", "SERIAL")
                resp_obj.setdefault("device", "MA_WALLET_PTY")
            out = json.dumps(resp_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except Exception as e:
            out = json.dumps({"type": "ERROR", "error": f"intern:{e.__class__.__name__}", "transport": "SERIAL", "device": "MA_WALLET_PTY"}, sort_keys=True, separators=(",", ":")).encode("utf-8")

        try:
            _write_frame(master_fd, out)
        except Exception:
            pass


def run_tcp() -> None:
    host = os.getenv("MA_WALLETD_HOST", "127.0.0.1").strip()
    port = int(os.getenv("MA_WALLETD_PORT", "7788").strip())
    with ThreadingTCPServer((host, port), WalletdHandler) as srv:
        print(f"walletd TCP listening on {host}:{port}", flush=True)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass


def main() -> None:
    mode = os.getenv("MA_WALLETD_MODE", "SERIAL").strip().upper()
    if mode == "TCP":
        run_tcp()
    else:
        run_serial()


if __name__ == "__main__":
    main()
