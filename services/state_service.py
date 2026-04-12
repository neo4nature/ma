"""State/persistence helpers extracted from the legacy monolith.

These helpers intentionally keep file formats and behavior unchanged while
making app.py smaller and easier to reason about.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable


def load_json(path: str, default: Any):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_users(users_file: str):
    return load_json(users_file, {'users': ['Neo', 'Lira']})


def save_users(users_file: str, payload):
    save_json(users_file, payload)


def load_messages(messages_file: str):
    return load_json(messages_file, {'threads': {}})


def save_messages(messages_file: str, payload):
    save_json(messages_file, payload)


def load_comm_rate(comm_rate_file: str):
    return load_json(comm_rate_file, {})


def save_comm_rate(comm_rate_file: str, payload):
    save_json(comm_rate_file, payload)


def ensure_user_records(
    usernames,
    *,
    comm_keys_dir: str,
    wallet_keys_dir: str,
    horizon_keys_dir: str,
    ensure_comm_keypair: Callable,
    ensure_user_wallet_keypair: Callable,
    ensure_user_horizon_keypair: Callable,
    ensure_account: Callable,
    list_usernames: Callable,
    base_dir: str,
):
    for u in usernames or []:
        u = (u or '').strip()
        if not u:
            continue
        ensure_comm_keypair(u, Path(comm_keys_dir))
        ensure_user_wallet_keypair(u, Path(wallet_keys_dir))
        ensure_user_horizon_keypair(u, Path(horizon_keys_dir))
        ensure_account(u, 1000.0)
    return {'users': list_usernames(base_dir)}


def ensure_wallet_secret(
    *,
    user: str,
    password: str,
    base_dir: str,
    wallet_keys_dir: str,
    get_user_secret: Callable,
    ensure_user_wallet_keypair: Callable,
    encrypt_private: Callable,
    vault_blob_cls,
    upsert_user_secret: Callable,
    set_wallet_priv_pem: Callable,
):
    u = (user or '').strip()
    if not u or not password:
        return

    s = get_user_secret(base_dir, u, 'wallet_secp256k1')
    if not s:
        priv_pem, pub_pem = ensure_user_wallet_keypair(u, Path(wallet_keys_dir))
        blob = encrypt_private(password, priv_pem, pub_pem.decode('utf-8', errors='replace'))
        upsert_user_secret(
            base_dir,
            u,
            'wallet_secp256k1',
            blob.pub,
            blob.enc_priv_b64,
            blob.salt_b64,
            blob.nonce_b64,
            blob.kdf_json,
        )
        try:
            user_safe = u.replace('/', '_').replace('..', '_')
            priv_path = Path(wallet_keys_dir) / f'{user_safe}.secp256k1.priv.pem'
            if priv_path.exists():
                priv_path.unlink()
        except Exception:
            pass
        set_wallet_priv_pem(u, priv_pem)
        return

    try:
        vb = vault_blob_cls(
            pub=str(s.get('pub') or ''),
            enc_priv_b64=str(s.get('enc_priv_b64') or ''),
            salt_b64=str(s.get('salt_b64') or ''),
            nonce_b64=str(s.get('nonce_b64') or ''),
            kdf_json=str(s.get('kdf_json') or '{}'),
        )
        from core.key_vault import decrypt_private
        priv_pem = decrypt_private(password, vb)
        set_wallet_priv_pem(u, priv_pem)
    except Exception:
        pass


def load_posts(posts_file: str):
    try:
        with open(posts_file, 'r', encoding='utf-8') as f:
            posts = json.load(f)
            return posts if isinstance(posts, list) else []
    except FileNotFoundError:
        return []


def save_posts(posts_file: str, posts: list) -> None:
    os.makedirs(os.path.dirname(posts_file), exist_ok=True)
    with open(posts_file, 'w', encoding='utf-8') as f:
        json.dump(posts, f, ensure_ascii=False, indent=2)


def load_media(media_file: str):
    try:
        with open(media_file, 'r', encoding='utf-8') as f:
            items = json.load(f)
            return items if isinstance(items, list) else []
    except FileNotFoundError:
        return []


def save_media(media_file: str, items: list) -> None:
    os.makedirs(os.path.dirname(media_file), exist_ok=True)
    with open(media_file, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


def decorate_media(items: list, *, verify_hash: Callable) -> list:
    now = time.time()
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        ii = dict(it)
        ts = ii.get('timestamp')
        if isinstance(ts, (int, float)):
            try:
                ii['minutes_ago'] = max(0, int((now - float(ts)) // 60))
            except Exception:
                pass
        mh = ii.get('manifest_hash_b64')
        sig = ii.get('signature_b64')
        author = ii.get('author')
        purpose = ii.get('purpose') or 'MEDIA_MANIFEST'
        if mh and sig and author:
            try:
                ii['verified'] = bool(verify_hash(mh, sig, author, purpose=purpose))
            except Exception:
                ii['verified'] = False
        else:
            ii['verified'] = False
        out.append(ii)
    return out


def decorate_posts(posts: list, *, verify_hash: Callable) -> list:
    now = time.time()
    out = []
    for p in posts or []:
        if not isinstance(p, dict):
            continue
        pp = dict(p)
        ts = pp.get('timestamp')
        if isinstance(ts, (int, float)):
            try:
                pp['minutes_ago'] = max(0, int((now - float(ts)) // 60))
            except Exception:
                pass
        mh = pp.get('manifest_hash_b64')
        sig = pp.get('signature_b64')
        author = pp.get('author')
        purpose = pp.get('purpose') or 'FID_POST'
        if mh and sig and author:
            try:
                pp['verified'] = bool(verify_hash(mh, sig, author, purpose=purpose))
            except Exception:
                pp['verified'] = False
        else:
            pp['verified'] = False
        out.append(pp)
    return out
