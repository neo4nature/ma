from __future__ import annotations

import time
from typing import Dict, Optional

# In-memory keystore for decrypted private keys (prototype).
# Nothing here is persisted. We clear entries on logout.

_WALLET_PRIV_PEM: Dict[str, bytes] = {}
_COMM_PRIV_RAW: Dict[str, bytes] = {}
_HORIZON_PRIV_RAW: Dict[str, bytes] = {}
_TS: Dict[str, float] = {}


def _touch(user: str) -> None:
    _TS[user] = time.time()


def set_wallet_priv_pem(user: str, pem: bytes) -> None:
    _WALLET_PRIV_PEM[user] = pem
    _touch(user)


def get_wallet_priv_pem(user: str) -> Optional[bytes]:
    return _WALLET_PRIV_PEM.get(user)


def set_comm_priv_raw(user: str, raw: bytes) -> None:
    _COMM_PRIV_RAW[user] = raw
    _touch(user)


def get_comm_priv_raw(user: str) -> Optional[bytes]:
    return _COMM_PRIV_RAW.get(user)


def set_horizon_priv_raw(user: str, raw: bytes) -> None:
    _HORIZON_PRIV_RAW[user] = raw
    _touch(user)


def get_horizon_priv_raw(user: str) -> Optional[bytes]:
    return _HORIZON_PRIV_RAW.get(user)


def clear_user(user: str) -> None:
    _WALLET_PRIV_PEM.pop(user, None)
    _COMM_PRIV_RAW.pop(user, None)
    _HORIZON_PRIV_RAW.pop(user, None)
    _TS.pop(user, None)
