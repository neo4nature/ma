import pytest
import importlib
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

from core.host_protocol import decode_device_hello_response, encode_device_hello_request
from core.firmware_bridge import _read_frame as bridge_read_frame, _write_frame as bridge_write_frame
from daemon.walletd import ThreadingTCPServer, WalletdHandler, _read_frame as walletd_read_frame, _write_frame as walletd_write_frame


def _reload_bridge(tmp_path, transport="INPROC"):
    os.environ["MA_DATA_DIR"] = str(tmp_path / "data")
    os.environ["MA_SECRETS_DIR"] = str(tmp_path / "secrets")
    os.environ["MA_SIGNER_MODE"] = "SOFTWARE"
    os.environ["MA_SIGNER_TRANSPORT"] = transport
    for mod in ["core.firmware_bridge", "wallet.tx_signer", "wallet.key_manager", "core.paths"]:
        if mod in sys.modules:
            del sys.modules[mod]
    import core.firmware_bridge as fb  # noqa: F401
    return importlib.reload(sys.modules["core.firmware_bridge"])


def test_sign_hash_via_firmware_inproc(tmp_path):
    fb = _reload_bridge(tmp_path)
    resp = fb.sign_hash_via_firmware(
        purpose="fid_login",
        payload_hash_b64="QUJDREVGR0g=",
        sender="neo",
        meta={"counter": 1, "nonce": b"1234567890abcdef"},
    )
    assert resp["status"] == "OK"
    assert resp["type"] == "SIGN_RESP"
    assert resp["purpose"] == "FID_LOGIN"
    assert resp["transport"] == "MOCK_PROTO"
    assert resp["sig_b64"]


def test_walletd_tcp_device_hello_and_sign(tmp_path):
    os.environ["MA_DEVICE_KEYS_DIR"] = str(tmp_path / "device_keys")
    with ThreadingTCPServer(("127.0.0.1", 0), WalletdHandler) as srv:
        host, port = srv.server_address
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection((host, port), timeout=2.0) as s:
                s.sendall(encode_device_hello_request({"req_id": "hello-1"}) + b"\n")
                raw = s.recv(4096).strip()
            hello = decode_device_hello_response(raw)
            assert hello["status"] == "OK"
            assert hello["fingerprint"].startswith("MA-HW-")
            assert hello["device_pub_b64"]

            os.environ["MA_SIGNER_TRANSPORT"] = "SOCKET"
            os.environ["MA_WALLETD_HOST"] = host
            os.environ["MA_WALLETD_PORT"] = str(port)
            fb = _reload_bridge(tmp_path, transport="SOCKET")
            resp = fb.sign_hash_via_firmware(
                purpose="compute_proof",
                payload_hash_b64="QUJDREVGR0g=",
                sender="neo",
                meta={"counter": 2, "nonce": b"abcdef1234567890"},
            )
            assert resp["status"] == "OK"
            assert resp["transport"] == "SOCKET"
            assert resp["purpose"] == "COMPUTE_PROOF"
            assert resp["sig_b64"]
        finally:
            srv.shutdown()
            thread.join(timeout=2.0)


def test_framing_roundtrip_and_crc_guard():
    rfd, wfd = os.pipe()
    try:
        payload = json.dumps({"ok": True}, sort_keys=True).encode("utf-8")
        bridge_write_frame(wfd, payload)
        assert bridge_read_frame(rfd) == payload
    finally:
        os.close(rfd)
        os.close(wfd)

    rfd2, wfd2 = os.pipe()
    try:
        payload = b'{"bad":true}'
        walletd_write_frame(wfd2, payload)
        raw = os.read(rfd2, 8 + len(payload))
        tampered = bytearray(raw)
        tampered[-1] ^= 0x01
        rfd3, wfd3 = os.pipe()
        try:
            os.write(wfd3, tampered)
            try:
                walletd_read_frame(rfd3)
                assert False, "expected bad_crc"
            except ValueError as e:
                assert "bad_crc" in str(e)
        finally:
            os.close(rfd3)
            os.close(wfd3)
    finally:
        os.close(rfd2)
        os.close(wfd2)



def test_serial_transport_fails_fast_on_bad_crc(tmp_path, monkeypatch):
    fb = _reload_bridge(tmp_path, transport="SERIAL")
    fake_port = tmp_path / "ttyMA0"
    fake_port.write_text("")
    monkeypatch.setenv("MA_SERIAL_PORT", str(fake_port))

    def _boom(fd):
        raise ValueError("bad_crc")

    monkeypatch.setattr(fb, "_read_frame", _boom)
    monkeypatch.setattr(fb, "_write_frame", lambda fd, payload: None)
    with pytest.raises(ValueError, match="bad_crc"):
        fb.sign_hash_via_firmware(
            purpose="fid_login",
            payload_hash_b64="QUJDREVGR0g=",
            sender="neo",
            meta={"counter": 3, "nonce": b"1234567890abcdef"},
        )


def test_serial_transport_times_out_on_silent_read(tmp_path, monkeypatch):
    fb = _reload_bridge(tmp_path, transport="SERIAL")
    fake_port = tmp_path / "ttyMA0"
    fake_port.write_text("")
    monkeypatch.setenv("MA_SERIAL_PORT", str(fake_port))
    monkeypatch.setenv("MA_SERIAL_TIMEOUT", "0.01")

    def _silent(fd):
        raise EOFError("tty_closed")

    class _Clock:
        def __init__(self):
            self.t = 0.0
        def __call__(self):
            self.t += 0.02
            return self.t

    monkeypatch.setattr(fb, "_read_frame", _silent)
    monkeypatch.setattr(fb, "_write_frame", lambda fd, payload: None)
    monkeypatch.setattr(fb.time, "monotonic", _Clock())

    with pytest.raises(TimeoutError, match="serial_timeout"):
        fb.sign_hash_via_firmware(
            purpose="fid_login",
            payload_hash_b64="QUJDREVGR0g=",
            sender="neo",
            meta={"counter": 4, "nonce": b"1234567890abcdef"},
        )


def test_walletd_framing_rejects_bad_length():
    rfd, wfd = os.pipe()
    try:
        os.write(wfd, b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00")
        try:
            walletd_read_frame(rfd)
            assert False, "expected bad_len"
        except ValueError as e:
            assert "bad_len" in str(e)
    finally:
        os.close(rfd)
        os.close(wfd)
