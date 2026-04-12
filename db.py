import os
import sqlite3
import time
import json
import re
import shutil
import subprocess
from typing import Optional, Dict, Any, List

from werkzeug.security import generate_password_hash

from core.paths import data_dir as _ma_data_dir


def _db_path(base_dir: str) -> str:
    # Single source of truth for data directory (defaults to runtime/).
    # base_dir is kept for backward compatibility, but path selection is centralized.
    _ = base_dir
    d = str(_ma_data_dir())
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "ma.db")


def connect(base_dir: str) -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(base_dir), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(base_dir: str) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          require_device INTEGER DEFAULT 0,
          device_fingerprint TEXT,
          created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          msg_id TEXT UNIQUE NOT NULL,
          sender TEXT NOT NULL,
          receiver TEXT NOT NULL,
          ts REAL NOT NULL,
          ciphertext_b64 TEXT,
          nonce_b64 TEXT,
          salt_b64 TEXT,
          aad_b64 TEXT,
          receiver_read INTEGER DEFAULT 0,
          v INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS user_secrets (
          user_id INTEGER NOT NULL,
          key_type TEXT NOT NULL,
          pub TEXT NOT NULL,
          enc_priv_b64 TEXT NOT NULL,
          salt_b64 TEXT NOT NULL,
          nonce_b64 TEXT NOT NULL,
          kdf_json TEXT NOT NULL,
          created_at REAL NOT NULL,
          PRIMARY KEY(user_id, key_type),
          FOREIGN KEY(user_id) REFERENCES users(id)
        );

        /* Simple compute job queue (prototype: next stage after live pools).
           Execution/worker network will be added later; for now this records requests. */
        CREATE TABLE IF NOT EXISTS compute_jobs (
          id TEXT PRIMARY KEY,
          owner TEXT NOT NULL,
          kind TEXT NOT NULL,
          src_relpath TEXT NOT NULL,
          status TEXT NOT NULL,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL,
          result_relpath TEXT,
          claimed_by TEXT,
          claimed_at REAL,
          result_hash_hex TEXT,
          proof_json TEXT,
          cost_units REAL NOT NULL DEFAULT 0,
          price_multiplier REAL NOT NULL DEFAULT 1.0,
          pricing_inputs_json TEXT,
          cancel_requested INTEGER DEFAULT 0,
          cancel_requested_at REAL,
          cancel_reason TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_messages_pair_ts ON messages(sender, receiver, ts);
        CREATE INDEX IF NOT EXISTS idx_messages_receiver_read ON messages(receiver, receiver_read, ts);

        CREATE TABLE IF NOT EXISTS contrib_settings (
          user_id INTEGER NOT NULL,
          slider_pos INTEGER NOT NULL DEFAULT 0,
          updated_at REAL NOT NULL,
          PRIMARY KEY(user_id)
        );

        -- Pricing state (v0.12): dynamic price multipliers for resources (compute, storage, etc.)
        CREATE TABLE IF NOT EXISTS pricing_state (
          resource TEXT PRIMARY KEY, -- 'compute' | 'storage'
          multiplier REAL NOT NULL DEFAULT 1.0,
          inputs_json TEXT, -- last snapshot of inputs
          updated_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_security (
          user_id INTEGER NOT NULL,
          recovery_pub_pem TEXT,
          updated_at REAL NOT NULL,
          PRIMARY KEY(user_id),
          FOREIGN KEY(user_id) REFERENCES users(id)
        );


        -- Feed/UI preferences (palette, theme, topics, etc.) stored as JSON
        CREATE TABLE IF NOT EXISTS user_preferences (
          user_id INTEGER NOT NULL,
          prefs_json TEXT NOT NULL,
          updated_at REAL NOT NULL,
          PRIMARY KEY(user_id),
          FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS storage_fields (
          user_id INTEGER NOT NULL,
          field_id INTEGER NOT NULL,
          gb INTEGER NOT NULL DEFAULT 1,
          days_committed INTEGER NOT NULL DEFAULT 7,
          start_ts REAL,
          status TEXT NOT NULL DEFAULT 'EMPTY', -- EMPTY | ACTIVE | MATURE | HARVESTED
          harvested_units INTEGER NOT NULL DEFAULT 0,
          last_harvest_ts REAL,
          PRIMARY KEY(user_id, field_id)
        );

        -- Per-device storage reservations (real disk allocation).
        -- This is the bridge between "declared storage" and actual reserved space.
        CREATE TABLE IF NOT EXISTS storage_reservations (
          user_id INTEGER NOT NULL,
          device_fingerprint TEXT NOT NULL,
          reserved_bytes INTEGER NOT NULL DEFAULT 0,
          reserve_path TEXT,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL,
          PRIMARY KEY(user_id, device_fingerprint),
          FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS horizon_receipts (
          receipt_id TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          kind TEXT NOT NULL, -- e.g. STORAGE_HARVEST | PRESENCE_REWARD | MARKET_PURCHASE | MEDIA_JOB
          payload_json TEXT NOT NULL,
          receipt_hash TEXT NOT NULL,
          horizon_sig_b64 TEXT NOT NULL,
          horizon_pub_pem TEXT NOT NULL,
          issued_ts REAL NOT NULL
        );

        -- Marketplace (v0.11): listings + purchases
        CREATE TABLE IF NOT EXISTS market_listings (
          listing_id TEXT PRIMARY KEY,
          seller TEXT NOT NULL,
          title TEXT NOT NULL,
          description TEXT,
          price REAL NOT NULL,
          currency TEXT NOT NULL DEFAULT 'LC',
          status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | RESERVED | SOLD | CANCELLED
          owner TEXT,
          asset_id TEXT, -- reserved for future Asset Ledger upgrade
          media_dir TEXT, -- relative path under data/
          thumb_path TEXT, -- relative path to studio thumbnail under data/
          created_ts REAL NOT NULL,
          updated_ts REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_market_listings_status_ts ON market_listings(status, created_ts);
        CREATE INDEX IF NOT EXISTS idx_market_listings_seller_ts ON market_listings(seller, created_ts);

        CREATE TABLE IF NOT EXISTS market_purchases (
          purchase_id TEXT PRIMARY KEY,
          listing_id TEXT NOT NULL,
          buyer TEXT NOT NULL,
          seller TEXT NOT NULL,
          amount REAL NOT NULL,
          currency TEXT NOT NULL DEFAULT 'LC',
          tx_id TEXT NOT NULL,
          horizon_receipt_id TEXT,
          ts REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_market_purchases_buyer_ts ON market_purchases(buyer, ts);
        CREATE INDEX IF NOT EXISTS idx_market_purchases_seller_ts ON market_purchases(seller, ts);

        -- Media processing jobs (light, local tools)
        CREATE TABLE IF NOT EXISTS media_jobs (
          job_id TEXT PRIMARY KEY,
          listing_id TEXT NOT NULL,
          status TEXT NOT NULL, -- QUEUED | PROCESSING | DONE | FAILED
          toolchain TEXT NOT NULL,
          artifact_hash TEXT,
          error TEXT,
          created_ts REAL NOT NULL,
          updated_ts REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_media_jobs_listing_ts ON media_jobs(listing_id, created_ts);
        """
    )
    conn.commit()

    # --- lightweight migrations (prototype) ---------------------------------
    # Keep DB forward-compatible across zip versions without a full migration framework.
    _ensure_table_columns(
        conn,
        table="compute_jobs",
        columns={
            # execution / cancel
            "claimed_by": "TEXT",
            "claimed_at": "REAL",
            "result_hash_hex": "TEXT",
            "proof_json": "TEXT",
            "cancel_requested": "INTEGER DEFAULT 0",
            "cancel_requested_at": "REAL",
            "cancel_reason": "TEXT",
            # pricing (v0.12+)
            "cost_units": "REAL NOT NULL DEFAULT 0",
            "price_multiplier": "REAL NOT NULL DEFAULT 1.0",
            "pricing_inputs_json": "TEXT",
            # escrow settlement (v0.14)
            "escrow_amount": "REAL NOT NULL DEFAULT 0",
            "escrow_status": "TEXT NOT NULL DEFAULT 'NONE'",
            "escrow_tx_id": "TEXT",
            "payout_tx_id": "TEXT",
            "refund_tx_id": "TEXT",
        },
    )

    _ensure_table_columns(
        conn,
        table="storage_reservations",
        columns={
            "reserved_bytes": "INTEGER NOT NULL DEFAULT 0",
            "reserve_path": "TEXT",
            "created_at": "REAL NOT NULL DEFAULT 0",
            "updated_at": "REAL NOT NULL DEFAULT 0",
        },
    )

    conn.commit()

    # bootstrap demo users if DB is empty
    cur.execute("SELECT COUNT(*) AS n FROM users")
    n = int(cur.fetchone()["n"])
    if n == 0:
        # local prototype defaults
        create_user(base_dir, "Neo", "demo")
        create_user(base_dir, "Lira", "demo")
    conn.close()


def _ensure_table_columns(conn: sqlite3.Connection, *, table: str, columns: Dict[str, str]) -> None:
    """Best-effort add missing columns (SQLite ALTER TABLE ADD COLUMN)."""
    try:
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        existing = {str(r[1]) for r in cur.fetchall()}  # type: ignore[index]
        for name, ctype in (columns or {}).items():
            if name in existing:
                continue
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ctype}")
    except Exception:
        # Never block app startup; worst case: a feature silently degrades.
        return


def create_user(base_dir: str, username: str, password: str) -> Dict[str, Any]:
    username = (username or "").strip()
    if not username:
        raise ValueError("empty_username")
    if len(username) > 32:
        raise ValueError("username_too_long")
    if not password or len(password) < 3:
        raise ValueError("password_too_short")

    conn = connect(base_dir)
    cur = conn.cursor()
    ph = generate_password_hash(password)
    cur.execute(
        "INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)",
        (username, ph, time.time()),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "username": username}


def get_user_by_username(base_dir: str, username: str) -> Optional[Dict[str, Any]]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def list_usernames(base_dir: str) -> List[str]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT username FROM users ORDER BY lower(username)")
    out = [r[0] for r in cur.fetchall()]
    conn.close()
    return out


def insert_message(base_dir: str, m: Dict[str, Any]) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO messages(msg_id, sender, receiver, ts, ciphertext_b64, nonce_b64, salt_b64, aad_b64, receiver_read, v)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """,
        (
            m.get("id"),
            m.get("sender"),
            m.get("receiver"),
            float(m.get("timestamp") or m.get("ts") or time.time()),
            m.get("ciphertext_b64"),
            m.get("nonce_b64"),
            m.get("salt_b64"),
            m.get("aad_b64"),
            int(m.get("receiver_read") or 0),
            int(m.get("v") or 1),
        ),
    )
    conn.commit()
    conn.close()


def fetch_thread(base_dir: str, a: str, b: str, limit: int = 50) -> List[Dict[str, Any]]:
    # fetch both directions
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM messages
        WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
        ORDER BY ts DESC
        LIMIT ?
        """,
        (a, b, b, a, int(limit)),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return list(reversed(rows))


def mark_thread_read(base_dir: str, me: str, peer: str) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE messages
        SET receiver_read=1
        WHERE receiver=? AND sender=? AND receiver_read=0
        """,
        (me, peer),
    )
    conn.commit()
    conn.close()


def list_conversations(base_dir: str, me: str) -> List[Dict[str, Any]]:
    """Return conversation list for UI: peer, last_ts, unread."""
    conn = connect(base_dir)
    cur = conn.cursor()

    # peers where me participated
    cur.execute(
        """
        SELECT
          CASE WHEN sender=? THEN receiver ELSE sender END AS peer,
          MAX(ts) AS last_ts
        FROM messages
        WHERE sender=? OR receiver=?
        GROUP BY peer
        ORDER BY last_ts DESC
        """,
        (me, me, me),
    )
    peers = [dict(r) for r in cur.fetchall()]

    out: List[Dict[str, Any]] = []
    for p in peers:
        peer = p["peer"]
        cur.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE receiver=? AND sender=? AND receiver_read=0",
            (me, peer),
        )
        unread = int(cur.fetchone()["n"])
        out.append({"peer": peer, "last_ts": float(p["last_ts"] or 0), "unread": unread})

    conn.close()
    return out


def set_device_binding(base_dir: str, username: str, require_device: int, fingerprint: str | None) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET require_device=?, device_fingerprint=? WHERE username=?",
        (int(require_device or 0), fingerprint, username),
    )
    conn.commit()
    conn.close()


def upsert_user_secret(
    base_dir: str,
    username: str,
    key_type: str,
    pub: str,
    enc_priv_b64: str,
    salt_b64: str,
    nonce_b64: str,
    kdf_json: str,
) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise ValueError("no_such_user")
    uid = int(row["id"])
    cur.execute(
        """
        INSERT INTO user_secrets(user_id, key_type, pub, enc_priv_b64, salt_b64, nonce_b64, kdf_json, created_at)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(user_id, key_type) DO UPDATE SET
          pub=excluded.pub,
          enc_priv_b64=excluded.enc_priv_b64,
          salt_b64=excluded.salt_b64,
          nonce_b64=excluded.nonce_b64,
          kdf_json=excluded.kdf_json
        """,
        (uid, key_type, pub, enc_priv_b64, salt_b64, nonce_b64, kdf_json, time.time()),
    )
    conn.commit()
    conn.close()


def get_user_secret(base_dir: str, username: str, key_type: str) -> Optional[Dict[str, Any]]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT id, require_device, device_fingerprint FROM users WHERE username=?", (username,))
    u = cur.fetchone()
    if not u:
        conn.close()
        return None
    uid = int(u["id"])
    cur.execute(
        "SELECT * FROM user_secrets WHERE user_id=? AND key_type=?",
        (uid, key_type),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_recent_messages(username: str, limit: int = 50):
    """Return recent messages involving username (encrypted payload not decrypted)."""
    db = _db_path()
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """
        SELECT msg_id, sender, receiver, ts, ciphertext_b64, is_read
        FROM messages
        WHERE sender=? OR receiver=?
        ORDER BY ts DESC
        LIMIT ?
        """,
        (username, username, int(limit)),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# --- Contrib & Storage (v0.1.3) -------------------------------------------------

def ensure_contrib_settings(base_dir: str, user_id: int) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM contrib_settings WHERE user_id = ?", (user_id,))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO contrib_settings(user_id, slider_pos, updated_at) VALUES(?,?,?)",
            (user_id, 0, time.time()),
        )
    conn.commit()
    conn.close()


def get_contrib_settings(base_dir: str, user_id: int) -> dict:
    ensure_contrib_settings(base_dir, user_id)
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT slider_pos, updated_at FROM contrib_settings WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return {"slider_pos": int(row["slider_pos"]), "updated_at": float(row["updated_at"])}


def set_contrib_slider(base_dir: str, user_id: int, slider_pos: int) -> dict:
    slider_pos = max(0, min(100, int(slider_pos)))
    ensure_contrib_settings(base_dir, user_id)
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE contrib_settings SET slider_pos = ?, updated_at = ? WHERE user_id = ?",
        (slider_pos, time.time(), user_id),
    )
    conn.commit()
    conn.close()
    return get_contrib_settings(base_dir, user_id)


def touch_contrib(base_dir: str, user_id: int) -> dict:
    """Refresh contrib_settings.updated_at without changing slider_pos.

    Used to keep the node "online" in the compute/storage pool without requiring
    the user to move the slider.
    """
    ensure_contrib_settings(base_dir, user_id)
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE contrib_settings SET updated_at = ? WHERE user_id = ?",
        (time.time(), user_id),
    )
    conn.commit()
    conn.close()
    return get_contrib_settings(base_dir, user_id)


def set_contrib_offline(base_dir: str, user_id: int) -> None:
    """Mark this user's node as offline for pool visibility.

    Keep slider_pos (user preference), but force updated_at=0 so the node
    disappears from the LIVE pool immediately.
    """
    ensure_contrib_settings(base_dir, user_id)
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE contrib_settings SET updated_at = ? WHERE user_id = ?",
        (0.0, user_id),
    )
    conn.commit()
    conn.close()


def list_active_compute_offers(base_dir: str, ttl_sec: int = 600, base_mem_mb: int = 256) -> list[dict]:
    """List active compute offers (prototype).

    Active = slider_pos>0 and updated recently.
    """
    ttl_sec = max(30, min(24 * 3600, int(ttl_sec)))
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.username as username, c.slider_pos as slider_pos, c.updated_at as updated_at
        FROM contrib_settings c
        JOIN users u ON u.id = c.user_id
        WHERE c.slider_pos > 0
        ORDER BY c.updated_at DESC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    out: list[dict] = []
    for r in rows:
        ts = float(r.get("updated_at") or 0.0)
        if now - ts > ttl_sec:
            continue
        pos = int(r.get("slider_pos") or 0)
        declared = int((base_mem_mb * pos) / 100)
        out.append(
            {
                "username": r.get("username") or "",
                "slider_pos": pos,
                "updated_at": ts,
                "declared_mem_mb": max(0, declared),
            }
        )
    return out


def list_active_storage_offers(base_dir: str, ttl_sec: int = 600) -> list[dict]:
    """List active storage offers (prototype).

    Storage visibility is also treated as LIVE and bound to the same heartbeat
    as compute (contrib_settings.updated_at). This prevents stale storage offers
    from staying visible forever when a node goes offline.

    A field offers 1GB when status is ACTIVE or MATURE.
    """
    ttl_sec = max(30, min(24 * 3600, int(ttl_sec)))
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.username as username,
               s.field_id as field_id,
               s.gb as gb,
               s.days_committed as days_committed,
               s.start_ts as start_ts,
               s.status as status,
               c.updated_at as updated_at
        FROM storage_fields s
        JOIN users u ON u.id = s.user_id
        LEFT JOIN contrib_settings c ON c.user_id = s.user_id
        WHERE s.status IN ('ACTIVE','MATURE')
        ORDER BY s.start_ts DESC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    out: list[dict] = []
    for r in rows:
        ts = float(r.get("updated_at") or 0.0)
        if now - ts > ttl_sec:
            continue
        out.append(
            {
                "username": r.get("username") or "",
                "field_id": int(r.get("field_id") or 0),
                "gb": int(r.get("gb") or 1),
                "days_committed": int(r.get("days_committed") or 0),
                "start_ts": float(r.get("start_ts") or 0.0) if r.get("start_ts") else None,
                "status": r.get("status") or "",
            }
        )
    return out


# ============================
# Storage reservations (per device) — real disk allocation
# ============================

STORAGE_USABLE_RATIO = float(os.getenv("MA_STORAGE_USABLE_RATIO", "0.5") or 0.5)


def _data_dir(base_dir: str) -> str:
    """Resolve runtime data dir used by the app."""
    data_dir = os.getenv("MA_DATA_DIR") or os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def _safe_fp(fp: str) -> str:
    fp = (fp or "").strip() or "unknown"
    fp = re.sub(r"[^a-zA-Z0-9_.-]+", "_", fp)
    return fp[:80]


def _reserve_dir(base_dir: str) -> str:
    d = os.path.join(_data_dir(base_dir), "storage_reserved")
    os.makedirs(d, exist_ok=True)
    return d


def _reserve_file_path(base_dir: str, user_id: int, device_fingerprint: str) -> str:
    fn = f"u{int(user_id)}_{_safe_fp(device_fingerprint)}.bin"
    return os.path.join(_reserve_dir(base_dir), fn)


def _free_bytes(path: str) -> int:
    st = os.statvfs(path)
    return int(st.f_bavail) * int(st.f_frsize)


def _fallocate(path: str, size_bytes: int) -> None:
    """Best-effort preallocate a file.

    Prefer Linux fallocate; fallback to a sparse file via truncate.
    """
    size_bytes = int(max(0, size_bytes))
    # Ensure parent dir exists
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # If fallocate is available, use it (this actually reserves blocks on many filesystems).
    fallocate_bin = shutil.which("fallocate")
    if fallocate_bin:
        subprocess.check_call([fallocate_bin, "-l", str(size_bytes), path])
        return
    # Fallback: create sparse file
    with open(path, "ab") as f:
        pass
    os.truncate(path, size_bytes)


def get_storage_reservation(base_dir: str, user_id: int, device_fingerprint: str) -> dict | None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id, device_fingerprint, reserved_bytes, reserve_path, created_at, updated_at "
        "FROM storage_reservations WHERE user_id=? AND device_fingerprint=?",
        (int(user_id), str(device_fingerprint or "")),
    )
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "user_id": int(r["user_id"]),
        "device_fingerprint": r["device_fingerprint"],
        "reserved_bytes": int(r["reserved_bytes"] or 0),
        "reserve_path": r["reserve_path"],
        "created_at": float(r["created_at"] or 0.0),
        "updated_at": float(r["updated_at"] or 0.0),
    }


def compute_target_reserved_bytes(base_dir: str, user_id: int) -> int:
    """Compute target reserved bytes for a user based on ACTIVE/MATURE fields.

    v0.1.2 rule (per-device reservation):
    - each ACTIVE/MATURE field contributes `gb` GB declared
    - we **reserve 100% of declared bytes** on local disk (hard reservation)
    - the Marketplace may still expose only a fraction (e.g. 50%) as "usable" to
      tolerate node loss/redundancy; that is a *pricing/availability* policy,
      not a disk-allocation policy.
    """
    ensure_storage_fields(base_dir, user_id, 4)
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "SELECT SUM(gb) as total_gb FROM storage_fields WHERE user_id=? AND status IN ('ACTIVE','MATURE')",
        (int(user_id),),
    )
    row = cur.fetchone()
    conn.close()
    total_gb = float(row["total_gb"] or 0.0) if row else 0.0
    declared_gb = max(0.0, total_gb)
    return int(round(declared_gb * (1024 ** 3)))


def sync_storage_reservation(base_dir: str, *, user_id: int, device_fingerprint: str) -> dict:
    """Ensure per-device reservation matches current declared storage.

    Rules (v0.1.3):
    - If target is 0: release reservation (delete file + DB row)
    - If target > current: grow reservation (preallocate on disk)
    - If target < current: **shrink reservation** (truncate file + update DB)

    Why shrink is important:
    - Users may disable storage or reduce ACTIVE/MATURE fields.
    - Keeping the old reservation would keep disk space pinned and can fill the machine.
    """
    user_id = int(user_id)
    device_fingerprint = (device_fingerprint or "").strip() or "unknown"
    target = compute_target_reserved_bytes(base_dir, user_id)
    now = time.time()

    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "SELECT reserved_bytes, reserve_path FROM storage_reservations WHERE user_id=? AND device_fingerprint=?",
        (user_id, device_fingerprint),
    )
    row = cur.fetchone()

    if target <= 0:
        # release (IMPORTANT): if a device fingerprint changed (e.g. soft session fp)
        # we still want to free disk on this machine. Therefore, when target is 0,
        # release *all* reservations for this user (best-effort).
        cur.execute(
            "SELECT reserve_path FROM storage_reservations WHERE user_id=?",
            (user_id,),
        )
        paths = [str(r["reserve_path"]) for r in cur.fetchall() if r and r["reserve_path"]]
        for p in paths:
            try:
                os.remove(p)
            except Exception:
                pass
        cur.execute(
            "DELETE FROM storage_reservations WHERE user_id=?",
            (user_id,),
        )
        conn.commit()
        conn.close()
        return {"ok": True, "target_bytes": 0, "reserved_bytes": 0, "released": True, "released_paths": len(paths)}

    current = int(row["reserved_bytes"] or 0) if row else 0
    reserve_path = str(row["reserve_path"] or "") if row else ""
    if not reserve_path:
        reserve_path = _reserve_file_path(base_dir, user_id, device_fingerprint)

    # Ensure we have enough free disk to grow (best-effort)
    effective = current
    if target > current:
        free_b = _free_bytes(_data_dir(base_dir))
        # allow some slack for DB/logs etc.
        slack = 64 * 1024 * 1024
        need = (target - current) + slack
        if free_b < need:
            conn.close()
            return {"ok": False, "error": "insufficient_disk", "free_bytes": free_b, "need_bytes": need, "target_bytes": target, "reserved_bytes": current}
        try:
            _fallocate(reserve_path, target)
            effective = target
        except Exception as e:
            conn.close()
            return {"ok": False, "error": f"reserve_failed:{e.__class__.__name__}", "target_bytes": target, "reserved_bytes": current}

    # Shrink reservation if user reduced declared storage.
    if target < current:
        try:
            # Truncation should release blocks on most filesystems.
            os.makedirs(os.path.dirname(reserve_path), exist_ok=True)
            if os.path.exists(reserve_path):
                os.truncate(reserve_path, target)
            effective = target
        except Exception as e:
            # If shrink fails, keep previous size (don't break runtime).
            try:
                conn.close()
            except Exception:
                pass
            return {
                "ok": False,
                "error": f"shrink_failed:{e.__class__.__name__}",
                "target_bytes": int(target),
                "reserved_bytes": int(current),
                "reserve_path": reserve_path,
            }

    # upsert
    if row is None:
        cur.execute(
            "INSERT INTO storage_reservations(user_id, device_fingerprint, reserved_bytes, reserve_path, created_at, updated_at) VALUES(?,?,?,?,?,?)",
            (user_id, device_fingerprint, int(effective), reserve_path, now, now),
        )
    else:
        cur.execute(
            "UPDATE storage_reservations SET reserved_bytes=?, reserve_path=?, updated_at=? WHERE user_id=? AND device_fingerprint=?",
            (int(effective), reserve_path, now, user_id, device_fingerprint),
        )
    conn.commit()
    conn.close()
    return {"ok": True, "target_bytes": int(target), "reserved_bytes": int(effective), "reserve_path": reserve_path}


def cancel_compute_job(base_dir: str, *, job_id: str, owner: str) -> bool:
    """Cancel a compute job (best-effort).

    Rules (v0.1 → v0.1.1):
    - only the owner can cancel
    - if still QUEUED and not claimed → immediately CANCELED
    - if already claimed/executing → mark CANCEL_REQUESTED (worker should honor it)
    """
    job_id = (job_id or "").strip()
    owner = (owner or "").strip()
    if not job_id or not owner:
        return False
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    # 1) fast path: queued & unclaimed
    cur.execute(
        """
        UPDATE compute_jobs
        SET status='CANCELED', updated_at=?, cancel_requested=1, cancel_requested_at=?, cancel_reason='owner_cancel'
        WHERE id=? AND owner=? AND status='QUEUED' AND (claimed_by IS NULL OR claimed_by='')
        """,
        (now, now, job_id, owner),
    )
    ok = cur.rowcount == 1

    # 2) soft-cancel: already claimed/working
    if not ok:
        cur.execute(
            """
            UPDATE compute_jobs
            SET status='CANCEL_REQUESTED', updated_at=?, cancel_requested=1, cancel_requested_at=?, cancel_reason='owner_cancel'
            WHERE id=? AND owner=? AND status IN ('CLAIMED','WORKING','CANCEL_REQUESTED')
            """,
            (now, now, job_id, owner),
        )
        ok = cur.rowcount == 1
    conn.commit()
    conn.close()
    return ok


def get_pricing_state(base_dir: str, resource: str = 'compute') -> dict:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute('SELECT resource, multiplier, inputs_json, updated_at FROM pricing_state WHERE resource=?', (resource,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {'resource': resource, 'multiplier': 1.0, 'inputs': None, 'updated_at': 0}
    try:
        inputs = json.loads(row['inputs_json']) if row['inputs_json'] else None
    except Exception:
        inputs = None
    return {'resource': row['resource'], 'multiplier': float(row['multiplier'] or 1.0), 'inputs': inputs, 'updated_at': float(row['updated_at'] or 0)}


def set_pricing_state(base_dir: str, *, resource: str, multiplier: float, inputs: dict | None) -> None:
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO pricing_state(resource, multiplier, inputs_json, updated_at)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(resource) DO UPDATE SET
          multiplier=excluded.multiplier,
          inputs_json=excluded.inputs_json,
          updated_at=excluded.updated_at
        """,
        (resource, float(multiplier), json.dumps(inputs or {}), now),
    )
    conn.commit()
    conn.close()


def count_compute_jobs_by_status(base_dir: str, statuses: list[str]) -> int:
    if not statuses:
        return 0
    conn = connect(base_dir)
    cur = conn.cursor()
    qmarks = ','.join(['?'] * len(statuses))
    cur.execute(f"SELECT COUNT(1) AS c FROM compute_jobs WHERE status IN ({qmarks})", tuple(statuses))
    row = cur.fetchone()
    conn.close()
    return int(row['c'] or 0)

def ensure_storage_fields(base_dir: str, user_id: int, count: int = 4) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    for fid in range(1, count + 1):
        cur.execute(
            "SELECT field_id FROM storage_fields WHERE user_id = ? AND field_id = ?",
            (user_id, fid),
        )
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO storage_fields(user_id, field_id, gb, days_committed, start_ts, status, harvested_units, last_harvest_ts) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (user_id, fid, 1, 7, None, "EMPTY", 0, None),
            )
    conn.commit()
    conn.close()


def _compute_stage(start_ts: float | None, days_committed: int, now: float) -> tuple[int, int, str]:
    if not start_ts:
        return 0, 0, "EMPTY"
    days_elapsed = int((now - float(start_ts)) // 86400) + 1
    if days_elapsed < 0:
        days_elapsed = 0
    stage = min(7, max(0, days_elapsed))
    status = "ACTIVE"
    if days_elapsed >= days_committed:
        status = "MATURE"
    return stage, days_elapsed, status


def list_storage_fields(base_dir: str, user_id: int) -> list[dict]:
    ensure_storage_fields(base_dir, user_id, 4)
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "SELECT field_id, gb, days_committed, start_ts, status, harvested_units, last_harvest_ts "
        "FROM storage_fields WHERE user_id = ? ORDER BY field_id",
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()

    now = time.time()
    out = []
    for r in rows:
        stage, days_elapsed, computed_status = _compute_stage(r["start_ts"], int(r["days_committed"]), now)
        status = str(r["status"] or computed_status)
        # keep computed status if ACTIVE->MATURE
        if status in ("ACTIVE", "MATURE") or status == "EMPTY":
            status = computed_status if computed_status != "EMPTY" else status
        out.append(
            {
                "field_id": int(r["field_id"]),
                "gb": int(r["gb"]),
                "days_committed": int(r["days_committed"]),
                "start_ts": float(r["start_ts"]) if r["start_ts"] else None,
                "stage": int(stage),
                "days_elapsed": int(days_elapsed),
                "status": status,
                "harvested_units": int(r["harvested_units"]),
                "last_harvest_ts": float(r["last_harvest_ts"]) if r["last_harvest_ts"] else None,
            }
        )
    return out


def start_storage_lease(base_dir: str, user_id: int, field_id: int, days_committed: int = 7) -> dict:
    ensure_storage_fields(base_dir, user_id, 4)
    field_id = int(field_id)
    if field_id < 1 or field_id > 4:
        raise ValueError("field_id must be 1..4")
    days_committed = max(1, min(30, int(days_committed)))
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE storage_fields SET days_committed = ?, start_ts = ?, status = ? WHERE user_id = ? AND field_id = ?",
        (days_committed, time.time(), "ACTIVE", user_id, field_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "field_id": field_id, "days_committed": days_committed}


def mark_storage_empty(base_dir: str, user_id: int, field_id: int) -> dict:
    ensure_storage_fields(base_dir, user_id, 4)
    field_id = int(field_id)
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE storage_fields SET start_ts = NULL, status = 'EMPTY' WHERE user_id = ? AND field_id = ?",
        (user_id, field_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "field_id": field_id}


def save_horizon_receipt(base_dir: str, receipt_id: str, user_id: int, kind: str, payload: dict, receipt_hash: str, sig_b64: str, pub_pem: str) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO horizon_receipts(receipt_id, user_id, kind, payload_json, receipt_hash, horizon_sig_b64, horizon_pub_pem, issued_ts) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (receipt_id, user_id, kind, json.dumps(payload, ensure_ascii=False), receipt_hash, sig_b64, pub_pem, time.time()),
    )
    conn.commit()
    conn.close()


def list_horizon_receipts(base_dir: str, user_id: int, limit: int = 20) -> list[dict]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "SELECT receipt_id, kind, payload_json, receipt_hash, horizon_sig_b64, horizon_pub_pem, issued_ts "
        "FROM horizon_receipts WHERE user_id = ? ORDER BY issued_ts DESC LIMIT ?",
        (user_id, int(limit)),
    )
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append(
            {
                "receipt_id": r["receipt_id"],
                "kind": r["kind"],
                "payload": json.loads(r["payload_json"]),
                "receipt_hash": r["receipt_hash"],
                "horizon_sig_b64": r["horizon_sig_b64"],
                "horizon_pub_pem": r["horizon_pub_pem"],
                "issued_ts": float(r["issued_ts"]),
            }
        )
    return out


# ============================
# Marketplace (v0.11)
# ============================


def create_market_listing(
    base_dir: str,
    listing_id: str,
    seller: str,
    title: str,
    description: str,
    price: float,
    currency: str = "LC",
    status: str = "ACTIVE",
    owner: str | None = None,
    asset_id: str | None = None,
    media_dir: str | None = None,
    thumb_path: str | None = None,
) -> dict:
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO market_listings(listing_id, seller, title, description, price, currency, status, owner, asset_id, media_dir, thumb_path, created_ts, updated_ts)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            listing_id,
            seller,
            title,
            description,
            float(price),
            currency,
            status,
            owner,
            asset_id,
            media_dir,
            thumb_path,
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "listing_id": listing_id}


def get_market_listing(base_dir: str, listing_id: str) -> Optional[dict]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT * FROM market_listings WHERE listing_id=?", (listing_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_market_listings(base_dir: str, status: str | None = "ACTIVE", limit: int = 200) -> list[dict]:
    conn = connect(base_dir)
    cur = conn.cursor()
    if status:
        cur.execute(
            "SELECT * FROM market_listings WHERE status=? ORDER BY created_ts DESC LIMIT ?",
            (status, int(limit)),
        )
    else:
        cur.execute("SELECT * FROM market_listings ORDER BY created_ts DESC LIMIT ?", (int(limit),))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def update_market_listing_status(base_dir: str, listing_id: str, status: str, owner: str | None = None) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE market_listings SET status=?, owner=?, updated_ts=? WHERE listing_id=?",
        (status, owner, time.time(), listing_id),
    )
    conn.commit()
    conn.close()


def reserve_market_listing(base_dir: str, listing_id: str) -> bool:
    """Best-effort reservation to reduce double-buy in UI.

    Returns True if reservation succeeded.
    """
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE market_listings SET status='RESERVED', updated_ts=? WHERE listing_id=? AND status='ACTIVE'",
        (time.time(), listing_id),
    )
    conn.commit()
    ok = cur.rowcount > 0
    conn.close()
    return ok


def cancel_market_listing(base_dir: str, listing_id: str) -> None:
    update_market_listing_status(base_dir, listing_id, 'CANCELLED', owner=None)


def mark_market_listing_sold(base_dir: str, listing_id: str, owner: str) -> None:
    update_market_listing_status(base_dir, listing_id, 'SOLD', owner=owner)


def update_listing_status(base_dir: str, listing_id: str, status: str, owner: str | None = None) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE market_listings SET status=?, owner=?, updated_ts=? WHERE listing_id=?",
        (status, owner, time.time(), listing_id),
    )
    conn.commit()
    conn.close()


def update_listing_media(base_dir: str, listing_id: str, media_dir: str | None, thumb_path: str | None) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE market_listings SET media_dir=?, thumb_path=?, updated_ts=? WHERE listing_id=?",
        (media_dir, thumb_path, time.time(), listing_id),
    )
    conn.commit()
    conn.close()


def insert_market_purchase(
    base_dir: str,
    purchase_id: str,
    listing_id: str,
    buyer: str,
    seller: str,
    amount: float,
    currency: str,
    tx_id: str,
    horizon_receipt_id: str | None,
) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO market_purchases(purchase_id, listing_id, buyer, seller, amount, currency, tx_id, horizon_receipt_id, ts)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            purchase_id,
            listing_id,
            buyer,
            seller,
            float(amount),
            currency,
            tx_id,
            horizon_receipt_id,
            time.time(),
        ),
    )
    conn.commit()
    conn.close()


def list_market_purchases_for_user(base_dir: str, username: str, limit: int = 200) -> list[dict]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM market_purchases
        WHERE buyer=? OR seller=?
        ORDER BY ts DESC LIMIT ?
        """,
        (username, username, int(limit)),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# ============================
# Media jobs (v0.11)
# ============================


def create_media_job(base_dir: str, job_id: str, listing_id: str, toolchain: str) -> None:
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO media_jobs(job_id, listing_id, status, toolchain, created_ts, updated_ts) VALUES(?,?,?,?,?,?)",
        (job_id, listing_id, "QUEUED", toolchain, now, now),
    )
    conn.commit()
    conn.close()


def update_media_job(base_dir: str, job_id: str, status: str, artifact_hash: str | None = None, error: str | None = None) -> None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        "UPDATE media_jobs SET status=?, artifact_hash=?, error=?, updated_ts=? WHERE job_id=?",
        (status, artifact_hash, error, time.time(), job_id),
    )
    conn.commit()
    conn.close()


def get_media_job(base_dir: str, job_id: str) -> Optional[dict]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT * FROM media_jobs WHERE job_id=?", (job_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# ============================
# User preferences (Feed/UI)
# ============================


def get_user_preferences(base_dir: str, user_id: int) -> Dict[str, Any]:
    """Return stored preferences JSON for a user, or an empty dict."""
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT prefs_json FROM user_preferences WHERE user_id=?", (int(user_id),))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {}
    try:
        return json.loads(row[0] or "{}") or {}
    except Exception:
        return {}


def set_user_preferences(base_dir: str, user_id: int, prefs: Dict[str, Any]) -> None:
    """Upsert user preferences JSON."""
    now = time.time()
    payload = json.dumps(prefs or {}, ensure_ascii=False, separators=(",", ":"))
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO user_preferences(user_id, prefs_json, updated_at)
        VALUES(?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET prefs_json=excluded.prefs_json, updated_at=excluded.updated_at
        """,
        (int(user_id), payload, now),
    )
    conn.commit()
    conn.close()



# ============================
# User security (v0.12)
# ============================

def get_user_security(base_dir: str, user_id: int) -> Dict[str, Any]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute("SELECT recovery_pub_pem, updated_at FROM user_security WHERE user_id=?", (int(user_id),))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {"recovery_pub_pem": None, "updated_at": None}
    return {"recovery_pub_pem": row[0], "updated_at": row[1]}


def set_user_recovery_pub(base_dir: str, user_id: int, recovery_pub_pem: str | None) -> None:
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO user_security(user_id, recovery_pub_pem, updated_at)
        VALUES(?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET recovery_pub_pem=excluded.recovery_pub_pem, updated_at=excluded.updated_at
        """,
        (int(user_id), recovery_pub_pem, now),
    )
    conn.commit()
    conn.close()


# ============================
# Compute jobs (v0.13 prototype)
# ============================

def create_compute_job(base_dir: str, job: Dict[str, Any]) -> None:
    """Insert a compute job record.

    Expected keys: id, owner, kind, src_relpath, status, created_at, updated_at, result_relpath(optional)
    """
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO compute_jobs(
          id, owner, kind, src_relpath, status, created_at, updated_at, result_relpath,
          cost_units, price_multiplier, pricing_inputs_json,
          escrow_amount, escrow_status, escrow_tx_id
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            job["id"],
            job["owner"],
            job["kind"],
            job["src_relpath"],
            job["status"],
            float(job["created_at"]),
            float(job["updated_at"]),
            job.get("result_relpath"),
            float(job.get("cost_units") or 0.0),
            float(job.get("price_multiplier") or 1.0),
            job.get("pricing_inputs_json"),
            float(job.get("escrow_amount") or 0.0),
            str(job.get("escrow_status") or "NONE"),
            job.get("escrow_tx_id"),
        ),
    )
    conn.commit()
    conn.close()


def list_compute_jobs_for_user(base_dir: str, owner: str, limit: int = 50) -> List[Dict[str, Any]]:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, owner, kind, src_relpath, status, created_at, updated_at, result_relpath,
               claimed_by, claimed_at, result_hash_hex,
               cost_units, price_multiplier, pricing_inputs_json,
               escrow_amount, escrow_status, escrow_tx_id, payout_tx_id, refund_tx_id,
               cancel_requested, cancel_requested_at, cancel_reason
        FROM compute_jobs
        WHERE owner=?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (owner, int(limit)),
    )
    rows = cur.fetchall()
    conn.close()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": r[0],
                "owner": r[1],
                "kind": r[2],
                "src_relpath": r[3],
                "status": r[4],
                "created_at": r[5],
                "updated_at": r[6],
                "result_relpath": r[7],
                "claimed_by": r[8],
                "claimed_at": r[9],
                "result_hash_hex": r[10],
                "cost_units": float(r[11] or 0.0),
                "price_multiplier": float(r[12] or 1.0),
                "pricing_inputs_json": r[13],
                "escrow_amount": float(r[14] or 0.0),
                "escrow_status": r[15],
                "escrow_tx_id": r[16],
                "payout_tx_id": r[17],
                "refund_tx_id": r[18],
                "cancel_requested": int(r[19] or 0),
                "cancel_requested_at": r[20],
                "cancel_reason": r[21],
            }
        )
    return out


def claim_next_compute_job(base_dir: str, *, executor: str, allow_owner: bool = True) -> Dict[str, Any] | None:
    """Atomically claim the oldest queued job (prototype scheduler)."""
    executor = (executor or "").strip()
    if not executor:
        return None
    now = time.time()
    conn = connect(base_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()
        if allow_owner:
            cur.execute(
                """
                SELECT id FROM compute_jobs
                WHERE status='QUEUED' AND (claimed_by IS NULL OR claimed_by='') AND (cancel_requested IS NULL OR cancel_requested=0)
                ORDER BY created_at ASC
                LIMIT 1
                """
            )
        else:
            cur.execute(
                """
                SELECT id FROM compute_jobs
                WHERE status='QUEUED' AND (claimed_by IS NULL OR claimed_by='') AND owner<>? AND (cancel_requested IS NULL OR cancel_requested=0)
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (executor,),
            )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return None
        job_id = str(row[0])

        cur.execute(
            """
            UPDATE compute_jobs
            SET status='WORKING', claimed_by=?, claimed_at=?, updated_at=?
            WHERE id=? AND status='QUEUED' AND (claimed_by IS NULL OR claimed_by='')
            """,
            (executor, now, now, job_id),
        )
        if cur.rowcount != 1:
            conn.rollback()
            return None
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return None
    finally:
        conn.close()

    return get_compute_job(base_dir, job_id)


def get_compute_job(base_dir: str, job_id: str) -> Dict[str, Any] | None:
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, owner, kind, src_relpath, status, created_at, updated_at, result_relpath,
               claimed_by, claimed_at, result_hash_hex, proof_json,
               cost_units, price_multiplier, pricing_inputs_json,
               escrow_amount, escrow_status, escrow_tx_id, payout_tx_id, refund_tx_id,
               cancel_requested, cancel_requested_at, cancel_reason
        FROM compute_jobs
        WHERE id=?
        """,
        (job_id,),
    )
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r[0],
        "owner": r[1],
        "kind": r[2],
        "src_relpath": r[3],
        "status": r[4],
        "created_at": r[5],
        "updated_at": r[6],
        "result_relpath": r[7],
        "claimed_by": r[8],
        "claimed_at": r[9],
        "result_hash_hex": r[10],
        "proof_json": r[11],
        "cost_units": float(r[12] or 0.0),
        "price_multiplier": float(r[13] or 1.0),
        "pricing_inputs_json": r[14],
        "escrow_amount": float(r[15] or 0.0),
        "escrow_status": r[16],
        "escrow_tx_id": r[17],
        "payout_tx_id": r[18],
        "refund_tx_id": r[19],
        "cancel_requested": int(r[20] or 0),
        "cancel_requested_at": r[21],
        "cancel_reason": r[22],
    }


def set_compute_job_settlement(
    base_dir: str,
    *,
    job_id: str,
    escrow_status: str,
    payout_tx_id: str | None = None,
    refund_tx_id: str | None = None,
) -> None:
    """Update settlement fields for a compute job (best-effort)."""
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE compute_jobs
        SET escrow_status=?, payout_tx_id=?, refund_tx_id=?, updated_at=?
        WHERE id=?
        """,
        (str(escrow_status or "NONE"), payout_tx_id, refund_tx_id, now, job_id),
    )
    conn.commit()
    conn.close()


def complete_compute_job(
    base_dir: str,
    *,
    job_id: str,
    status: str,
    result_relpath: str | None,
    result_hash_hex: str | None,
    proof_json: str | None,
) -> None:
    now = time.time()
    conn = connect(base_dir)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE compute_jobs
        SET status=?, result_relpath=?, result_hash_hex=?, proof_json=?, updated_at=?
        WHERE id=?
        """,
        (status, result_relpath, result_hash_hex, proof_json, now, job_id),
    )
    conn.commit()
    conn.close()
