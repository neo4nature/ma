from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory, send_file, abort, g
import secrets
import os
import json
import time
import uuid
import base64
import hashlib
import io
from pathlib import Path
from PIL import Image

from core.paths import data_dir as _data_dir, secrets_dir as _secrets_dir
from core.safe_fs import safe_mkdirs, safe_resolve_file, tighten_dir_perms, UnsafePath

from db import (
    init_db,
    create_user,
    get_user_by_username,
    list_usernames,
    insert_message,
    fetch_thread,
    list_conversations,
    mark_thread_read,
    set_device_binding,
    get_user_secret,
    upsert_user_secret,
    get_contrib_settings,
    set_contrib_slider,
    touch_contrib,
    set_contrib_offline,
    list_active_compute_offers,
    list_storage_fields,
    start_storage_lease,
    mark_storage_empty,
    sync_storage_reservation,
    list_active_storage_offers,
    save_horizon_receipt,
    list_horizon_receipts,
    create_market_listing,
    list_market_listings,
    get_market_listing,
    reserve_market_listing,
    mark_market_listing_sold,
    update_market_listing_status,
    cancel_market_listing,
    insert_market_purchase,
    create_compute_job,
    list_compute_jobs_for_user,
    claim_next_compute_job,
    get_compute_job,
    complete_compute_job,
    cancel_compute_job,
    set_compute_job_settlement,
    list_market_purchases_for_user,
    update_listing_media,
    get_user_preferences,
    set_user_preferences,
    get_user_security,
    set_user_recovery_pub,
    get_pricing_state,
    set_pricing_state,
    count_compute_jobs_by_status,
)
from werkzeug.security import check_password_hash

from wallet.tx_signer import sign_transaction, sign_hash, verify_hash
from wallet.key_manager import load_public_key_pem
from wallet.state import load_state, apply_transaction, ensure_account
from core.horizon import evaluate_transaction
from core.firmware_bridge import sign_transaction_via_firmware, device_hello_via_firmware, sign_hash_via_firmware
from core.device_identity import verify_device_hello
from core.rounds import add_event_to_round, get_rounds, get_round_state
from core.event_chain import read_events, verify_full_chain, build_proof, verify_proof_bundle, append_event, export_events, import_events
from core.storage_chunks import chunk_and_store, open_chunk
from core.peer_router import load_peers as _load_peers, ensure_chunk_present as _ensure_chunk_present
from core.pin_store import load_pins as _load_pins, add_pins as _add_pins
from core.storage_assemble import (
    parse_chunk_list,
    compute_assembly_id,
    save_assembly,
    load_assembly,
    estimate_total_bytes,
    iter_assembled_bytes,
)
from core.comm_crypto import ensure_comm_keypair, encrypt_for_pair, decrypt_for_pair, _b64e, _b64d
from core.horizon_messages import evaluate_message
from core.horizon_signer import sign_horizon_receipt
from wallet.user_keys import ensure_user_wallet_keypair, rotate_user_keypair
from wallet.horizon_keys import ensure_user_horizon_keypair

from core.key_vault import encrypt_private, VaultBlob
from core.ram_keystore import set_wallet_priv_pem, clear_user as clear_ram_user

from tools.photo_tools import process_product_photos
from services.state_service import (
    load_json as _state_load_json,
    save_json as _state_save_json,
    load_users as _state_load_users,
    save_users as _state_save_users,
    load_messages as _state_load_messages,
    save_messages as _state_save_messages,
    load_comm_rate as _state_load_comm_rate,
    save_comm_rate as _state_save_comm_rate,
    ensure_user_records as _state_ensure_user_records,
    ensure_wallet_secret as _state_ensure_wallet_secret,
    load_posts as _state_load_posts,
    save_posts as _state_save_posts,
    load_media as _state_load_media,
    save_media as _state_save_media,
    decorate_media as _state_decorate_media,
    decorate_posts as _state_decorate_posts,
)


app = Flask(__name__)

# ---- Security: secret key / session hardening ----
# Never rely on a constant default secret in real deployments.
_sek = os.getenv("MA_SECRET_KEY")
if not _sek:
    # Dev-friendly: generate a random key and persist under MA_SECRETS_DIR.
    # Production should set MA_SECRET_KEY explicitly.
    try:
        # Persist dev secret under secrets dir (not under runtime marker root).
        _rk_dir = str(_secrets_dir())
        os.makedirs(_rk_dir, exist_ok=True)
        _rk_path = os.path.join(_rk_dir, ".ma_secret_key")
        if os.path.exists(_rk_path):
            _sek = open(_rk_path, "r", encoding="utf-8").read().strip()
        else:
            _sek = secrets.token_hex(32)
            with open(_rk_path, "w", encoding="utf-8") as f:
                f.write(_sek)
            try:
                os.chmod(_rk_path, 0o600)
            except Exception:
                pass
        os.environ["MA_SECRET_KEY"] = _sek
    except Exception:
        _sek = secrets.token_hex(32)
        os.environ["MA_SECRET_KEY"] = _sek

app.secret_key = _sek
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# --- Stable soft device fingerprint (important for per-device reservations) ---
# In software-only mode we still need a *stable* identifier on a given browser,
# otherwise storage reservations may become orphaned when the session is cleared.
_DEVICE_FP_COOKIE = "ma_device_fp"


@app.before_request
def _ensure_device_fp_cookie():
    """Ensure a long-lived soft device id exists (best-effort).

    Stored in a separate cookie (not in session) so it survives logout.
    """
    try:
        fp = (request.cookies.get(_DEVICE_FP_COOKIE) or "").strip()
        if not fp:
            fp = "soft-" + uuid.uuid4().hex
            g._set_device_fp_cookie = fp
        else:
            g._set_device_fp_cookie = None
        g._device_fp_cookie = fp
    except Exception:
        g._set_device_fp_cookie = None
        g._device_fp_cookie = ""


@app.after_request
def _maybe_set_device_fp_cookie(resp):
    try:
        fp = getattr(g, "_set_device_fp_cookie", None)
        if fp:
            # ~2 years
            resp.set_cookie(_DEVICE_FP_COOKIE, fp, max_age=60 * 60 * 24 * 730, httponly=False, samesite="Lax")
    except Exception:
        pass
    return resp


# --- Minimal i18n (prototype) -------------------------------------
from core.i18n import LANGS, install_i18n
from core.security import install_security

install_i18n(app, get_user_by_username, get_user_preferences)
install_security(app)
# -----------------------------------------------


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Data / secrets roots -------------------------------------------------
# MA_DATA_DIR and MA_SECRETS_DIR are the single source of truth for on-disk
# locations. They may point to encrypted volumes. They may also be symlinks.
# What we *must* prevent is: symlink escapes *inside* those trees.
DATA_DIR = str(_data_dir())
SECRETS_DIR = str(_secrets_dir())

# Create core subtrees with symlink-hardening.
_data_root = Path(DATA_DIR)
_secrets_root = Path(SECRETS_DIR)
tighten_dir_perms(_data_root, 0o700)
tighten_dir_perms(_secrets_root, 0o700)

# Public media directory (safe to serve via HTTP). NEVER serve the whole DATA_DIR.
PUBLIC_MEDIA_DIR = str(safe_mkdirs(_data_root, "public_media"))
tighten_dir_perms(Path(PUBLIC_MEDIA_DIR), 0o700)


POSTS_FILE = os.path.join(DATA_DIR, "posts_seed.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
MESSAGES_FILE = os.path.join(DATA_DIR, "messages.json")
DB_FILE = os.path.join(DATA_DIR, "ma.db")

# Sensitive keys belong under MA_SECRETS_DIR (not under general data).
COMM_KEYS_DIR = str(safe_mkdirs(_secrets_root, "keys_comm"))
WALLET_KEYS_DIR = str(safe_mkdirs(_secrets_root, "keys_wallet"))
HORIZON_KEYS_DIR = str(safe_mkdirs(_secrets_root, "keys_horizon"))

os.environ["MA_DATA_DIR"] = DATA_DIR
os.environ["MA_SECRETS_DIR"] = SECRETS_DIR
os.environ["MA_WALLET_KEYS_DIR"] = WALLET_KEYS_DIR
os.environ["MA_COMM_KEYS_DIR"] = COMM_KEYS_DIR
os.environ["MA_HORIZON_KEYS_DIR"] = HORIZON_KEYS_DIR
SIGNER_MODE = os.getenv('MA_SIGNER_MODE', 'SOFTWARE').strip().upper()
WORKER_TICK_TOKEN = os.getenv('MA_WORKER_TICK_TOKEN', '').strip()

HORIZON_MASTER_KEYS_DIR = str(Path(DATA_DIR) / "keys_horizon_master")
COMM_RATE_FILE = os.path.join(DATA_DIR, 'comm_rate.json')
ROUNDS_STATE_FILE = os.path.join(DATA_DIR, 'round_state.json')
ROUNDS_FILE = os.path.join(DATA_DIR, 'rounds.json')
EVENT_CHAIN_LOG = os.path.join(DATA_DIR, 'event_chain.jsonl')
MEDIA_FILE = os.path.join(DATA_DIR, 'media_seed.json')
EVENT_CHAIN_DIR = DATA_DIR


# ---- Pricing (compute multiplier v0.12) ------------------------------
COMPUTE_BASE_COST_UNITS = float(os.getenv('MA_COMPUTE_BASE_COST_UNITS', '1.0'))
COMPUTE_PRICE_MIN = float(os.getenv('MA_COMPUTE_PRICE_MIN', '0.5'))
COMPUTE_PRICE_MAX = float(os.getenv('MA_COMPUTE_PRICE_MAX', '5.0'))
COMPUTE_PRICE_ALPHA = float(os.getenv('MA_COMPUTE_PRICE_ALPHA', '0.2'))  # smoothing
COMPUTE_Q0 = float(os.getenv('MA_COMPUTE_Q0', '5'))
COMPUTE_U0 = float(os.getenv('MA_COMPUTE_U0', '0.8'))
COMPUTE_A = float(os.getenv('MA_COMPUTE_A', '1.0'))
COMPUTE_B = float(os.getenv('MA_COMPUTE_B', '1.0'))

# ---- LifeCoin settlement (compute escrow) ----------------------------
# We do NOT create a new token. We reuse the existing LifeCoin balances.
ESCROW_ACCOUNT = os.getenv('MA_ESCROW_ACCOUNT', 'MA_ESCROW').strip() or 'MA_ESCROW'
TREASURY_ACCOUNT = os.getenv('MA_TREASURY_ACCOUNT', 'MA_TREASURY').strip() or 'MA_TREASURY'
COMPUTE_TREASURY_CUT = float(os.getenv('MA_COMPUTE_TREASURY_CUT', '0.0'))  # 0.0 = no fee in v0.14

def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def _tick_compute_pricing() -> dict:
    # demand
    queue_depth = count_compute_jobs_by_status(BASE_DIR, ['QUEUED'])
    working = count_compute_jobs_by_status(BASE_DIR, ['WORKING','CLAIMED'])
    # supply proxy
    compute_nodes = list_active_compute_offers(BASE_DIR, ttl_sec=120, base_mem_mb=256)
    capacity = max(1, len(compute_nodes))
    utilization = _clamp(working / float(capacity), 0.0, 1.0)

    q_norm = _clamp(queue_depth / float(COMPUTE_Q0), 0.0, 1.0)
    u_norm = _clamp(utilization / float(COMPUTE_U0), 0.0, 1.0)

    raw = (1.0 + COMPUTE_A * q_norm) * (1.0 + COMPUTE_B * u_norm)
    prev = get_pricing_state(BASE_DIR, 'compute').get('multiplier', 1.0)
    mult = (1.0 - COMPUTE_PRICE_ALPHA) * float(prev) + COMPUTE_PRICE_ALPHA * float(raw)
    mult = _clamp(mult, COMPUTE_PRICE_MIN, COMPUTE_PRICE_MAX)
    inputs = {
        'queue_depth': int(queue_depth),
        'working': int(working),
        'capacity': int(capacity),
        'utilization': float(utilization),
        'raw': float(raw),
    }
    set_pricing_state(BASE_DIR, resource='compute', multiplier=mult, inputs=inputs)
    return {'multiplier': mult, 'inputs': inputs}

# Local blobstore (prototype for media chunking)
BLOB_DIR = str(safe_mkdirs(_data_root, "blobstore/chunks"))

# Pinned chunks (protected from cache eviction)
PINS_FILE = os.path.join(DATA_DIR, 'pins.json')

# Peer reputation
PEER_STATS_FILE = os.path.join(DATA_DIR, 'peer_stats.json')

# Peer routing (manual peers list in runtime/peers.json)
PEERS_FILE = os.path.join(DATA_DIR, 'peers.json')
BLOB_CACHE_MAX_MB = int(os.getenv('MA_BLOB_CACHE_MAX_MB', '1024'))

def _peers():
    return _load_peers(PEERS_FILE)

def _ensure_chunk(chunk_id: str) -> None:
    peers = _peers()
    cache_max_bytes = None if BLOB_CACHE_MAX_MB <= 0 else BLOB_CACHE_MAX_MB * 1024 * 1024
    pins = _load_pins(PINS_FILE)
    ok = _ensure_chunk_present(
        BLOB_DIR,
        chunk_id,
        peers,
        timeout_s=5.0,
        cache_max_bytes=cache_max_bytes,
        pinned=pins,
        peer_stats_file=PEER_STATS_FILE,
    )
    if not ok:
        raise FileNotFoundError('chunk_not_found')



# Initialize SQLite (v0.9)
init_db(BASE_DIR)

# In-memory FID-style challenges (prototype)
_FID_CHALLENGES: dict[str, dict] = {}


def require_login(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("auth.login_route", next=request.path))
        return fn(*args, **kwargs)

    return wrapper


def current_user() -> str | None:
    return session.get("username")

def current_user_id() -> int:
    u = current_user()
    if not u:
        raise RuntimeError('not_logged_in')
    row = get_user_by_username(BASE_DIR, u)
    if not row:
        raise RuntimeError('user_not_found')
    return int(row['id'])


def current_device_fingerprint() -> str:
    """Best-effort device fingerprint for per-device resource reservations.

    - In firmware mode, the user may have a bound fingerprint in the profile.
    - In software mode, we generate a stable per-session/browser fingerprint.
    """
    u = current_user()
    if not u:
        return "unknown"
    row = get_user_by_username(BASE_DIR, u) or {}
    fp = (row.get("device_fingerprint") or "").strip()
    if fp:
        return fp
    # software fallback: stable per-browser cookie (survives logout)
    fp_cookie = getattr(g, "_device_fp_cookie", "") or (request.cookies.get(_DEVICE_FP_COOKIE) or "")
    fp_cookie = (fp_cookie or "").strip()
    if fp_cookie:
        return fp_cookie
    # ultimate fallback (should be rare)
    if not session.get("soft_device_fp"):
        session["soft_device_fp"] = "soft-" + uuid.uuid4().hex
    return str(session.get("soft_device_fp"))




def _worker_tick_authorized() -> bool:
    from services.compute_runtime_service import worker_tick_authorized
    return worker_tick_authorized(configured_token=WORKER_TICK_TOKEN)


def _refund_compute_job_escrow_once(job_id: str, *, reason: str) -> dict:
    from services.compute_runtime_service import refund_compute_job_escrow_once
    return refund_compute_job_escrow_once(
        base_dir=BASE_DIR,
        job_id=str(job_id),
        reason=reason,
        escrow_account=ESCROW_ACCOUNT,
        get_compute_job=get_compute_job,
        set_compute_job_settlement=set_compute_job_settlement,
        wallet_transfer_internal=_wallet_transfer_internal,
    )

def _b64e_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def _sha256_b64(b: bytes) -> str:
    return _b64e_bytes(hashlib.sha256(b).digest())


def _make_login_challenge(username: str) -> dict:
    """Create a short-lived login challenge for wallet-based login."""
    now = int(time.time())
    chal_id = uuid.uuid4().hex
    chal = {
        "id": chal_id,
        "realm": "MA_FID_LOGIN",
        "username": username,
        "nonce": uuid.uuid4().hex,
        "ts": now,
        "exp": now + 120,
    }
    _FID_CHALLENGES[chal_id] = chal
    return chal


def _challenge_payload_hash_b64(chal: dict) -> str:
    canonical = json.dumps(chal, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_b64(canonical)






def _load_json(path, default):
    return _state_load_json(path, default)


def _save_json(path, data):
    return _state_save_json(path, data)


def load_users():
    return _state_load_users(USERS_FILE)


def save_users(payload):
    return _state_save_users(USERS_FILE, payload)


def load_messages():
    return _state_load_messages(MESSAGES_FILE)


def save_messages(payload):
    return _state_save_messages(MESSAGES_FILE, payload)


def load_comm_rate():
    return _state_load_comm_rate(COMM_RATE_FILE)


def save_comm_rate(payload):
    return _state_save_comm_rate(COMM_RATE_FILE, payload)


def ensure_user_records(usernames):
    return _state_ensure_user_records(
        usernames,
        comm_keys_dir=COMM_KEYS_DIR,
        wallet_keys_dir=WALLET_KEYS_DIR,
        horizon_keys_dir=HORIZON_KEYS_DIR,
        ensure_comm_keypair=ensure_comm_keypair,
        ensure_user_wallet_keypair=ensure_user_wallet_keypair,
        ensure_user_horizon_keypair=ensure_user_horizon_keypair,
        ensure_account=ensure_account,
        list_usernames=list_usernames,
        base_dir=BASE_DIR,
    )


def ensure_wallet_secret(user: str, password: str) -> None:
    return _state_ensure_wallet_secret(
        user=user,
        password=password,
        base_dir=BASE_DIR,
        wallet_keys_dir=WALLET_KEYS_DIR,
        get_user_secret=get_user_secret,
        ensure_user_wallet_keypair=ensure_user_wallet_keypair,
        encrypt_private=encrypt_private,
        vault_blob_cls=VaultBlob,
        upsert_user_secret=upsert_user_secret,
        set_wallet_priv_pem=set_wallet_priv_pem,
    )


def _bootstrap_default_users():
    """Create demo users in DB on first run (local prototype)."""
    existing = list_usernames(BASE_DIR)
    if existing:
        return
    # Create defaults with password 'demo'
    for u in ["Neo", "Lira"]:
        try:
            create_user(BASE_DIR, u, "demo")
        except Exception:
            pass
    # ensure keys + accounts
    ensure_user_records(["Neo", "Lira"])
    # encrypt wallet keys for demo users
    try:
        for u in ["Neo", "Lira"]:
            ensure_wallet_secret(u, "demo")
    except Exception:
        pass

def load_posts():
    return _state_load_posts(POSTS_FILE)


def save_posts(posts: list) -> None:
    return _state_save_posts(POSTS_FILE, posts)


def load_media():
    return _state_load_media(MEDIA_FILE)


def save_media(items: list) -> None:
    return _state_save_media(MEDIA_FILE, items)


def _decorate_media(items: list) -> list:
    return _state_decorate_media(items, verify_hash=verify_hash)


def _decorate_posts(posts: list) -> list:
    return _state_decorate_posts(posts, verify_hash=verify_hash)


def home():
    me = current_user()
    ping_enabled = False
    if me:
        try:
            uid = current_user_id()
            st = get_contrib_settings(BASE_DIR, uid)
            slider = int(st.get("slider_pos") or 0)
            fields = list_storage_fields(BASE_DIR, uid)
            storage_active = any(f.get("status") in ("ACTIVE", "MATURE") for f in fields)
            ping_enabled = (slider > 0) or storage_active
        except Exception:
            ping_enabled = False
    return render_template("home.html", me=me, ping_enabled=ping_enabled)


def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        if not username or not password:
            flash("Podaj nazwę i hasło.")
            return render_template("register.html", me=current_user())
        try:
            create_user(BASE_DIR, username, password)
        except Exception:
            flash("Taki użytkownik już istnieje.")
            return render_template("register.html", me=current_user())

        # keys + initial funds
        ensure_user_records([username])
        ensure_wallet_secret(username, password)
        session["username"] = username
        return redirect("/comm")

    return render_template("register.html", me=current_user())


def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        user = get_user_by_username(BASE_DIR, username)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Błędna nazwa lub hasło.")
            return render_template("login.html", me=current_user())
        # Optional device bind gate
        try:
            require_dev = int(user.get("require_device") or 0)
            fp = user.get("device_fingerprint")
        except Exception:
            require_dev = 0
            fp = None
        if require_dev:
            if SIGNER_MODE != 'FIRMWARE':
                flash("Logowanie wymaga urządzenia (tryb firmware).")
                return render_template("login.html", me=current_user())
            try:
                di = verify_device_hello(device_hello_via_firmware())
                if not di.ok:
                    flash("Nie wykryto urządzenia.")
                    return render_template("login.html", me=current_user())
                if fp and di.fingerprint != fp:
                    flash("Fingerprint urządzenia nie pasuje do przypisanego.")
                    return render_template("login.html", me=current_user())
            except Exception:
                flash("Nie udało się zweryfikować urządzenia.")
                return render_template("login.html", me=current_user())

        session["username"] = username
        ensure_wallet_secret(username, password)
        nxt = request.args.get("next") or "/comm"
        return redirect(nxt)
    return render_template("login.html", me=current_user())


# --- Wallet-based login (FID-style) ---
def fid_challenge():
    """Create a short-lived challenge for wallet-based login.

    Request JSON: {"username": "Neo"}
    Response JSON: {challenge, payload_hash_b64}
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"ok": False, "error": "missing_username"}), 400
    user = get_user_by_username(BASE_DIR, username)
    if not user:
        return jsonify({"ok": False, "error": "user_not_found"}), 404

    chal = _make_login_challenge(username)
    return jsonify({
        "ok": True,
        "challenge": chal,
        "payload_hash_b64": _challenge_payload_hash_b64(chal),
        "purpose": "FID_LOGIN",
        "expires_in": 120,
    })


def fid_verify():
    """Verify wallet signature for a challenge and create a session."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    chal_id = (data.get("challenge_id") or "").strip()
    sig_b64 = (data.get("sig_b64") or "").strip()
    if not (username and chal_id and sig_b64):
        return jsonify({"ok": False, "error": "missing_fields"}), 400
    chal = _FID_CHALLENGES.get(chal_id)
    if not chal:
        return jsonify({"ok": False, "error": "challenge_not_found"}), 404
    if (chal.get("username") or "").strip() != username:
        return jsonify({"ok": False, "error": "challenge_user_mismatch"}), 400
    if int(chal.get("exp") or 0) < int(time.time()):
        _FID_CHALLENGES.pop(chal_id, None)
        return jsonify({"ok": False, "error": "challenge_expired"}), 400

    payload_hash_b64 = _challenge_payload_hash_b64(chal)
    ok = verify_hash(payload_hash_b64, sig_b64, signer=username, purpose="FID_LOGIN")
    if not ok:
        return jsonify({"ok": False, "error": "bad_signature"}), 401

    # success → session
    session["username"] = username
    _FID_CHALLENGES.pop(chal_id, None)
    return jsonify({"ok": True, "username": username})


def fid_login_wallet():
    """One-shot wallet login helper (server asks walletd to sign).

    Useful for the prototype where the browser doesn't talk to the wallet directly.
    Request JSON: {"username": "Neo"}
    Response JSON: {ok, username}
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"ok": False, "error": "missing_username"}), 400
    user = get_user_by_username(BASE_DIR, username)
    if not user:
        return jsonify({"ok": False, "error": "user_not_found"}), 404

    chal = _make_login_challenge(username)
    payload_hash_b64 = _challenge_payload_hash_b64(chal)

    # Ask wallet to sign
    try:
        if SIGNER_MODE == 'FIRMWARE':
            resp = sign_hash_via_firmware("FID_LOGIN", payload_hash_b64, sender=username, meta={"req_id": chal["id"]})
            sig_b64 = (resp.get("sig_b64") or "").strip()
        else:
            # Software signer (prototype): uses local key for username
            sig_b64 = sign_hash(payload_hash_b64, signer=username, purpose="FID_LOGIN")
    except Exception as e:
        _FID_CHALLENGES.pop(chal.get("id"), None)
        return jsonify({"ok": False, "error": f"sign_failed:{e.__class__.__name__}"}), 500

    if not sig_b64:
        _FID_CHALLENGES.pop(chal.get("id"), None)
        return jsonify({"ok": False, "error": "empty_signature"}), 500

    # Verify (defense-in-depth)
    ok = verify_hash(payload_hash_b64, sig_b64, signer=username, purpose="FID_LOGIN")
    if not ok:
        _FID_CHALLENGES.pop(chal.get("id"), None)
        return jsonify({"ok": False, "error": "bad_signature"}), 401

    session["username"] = username
    _FID_CHALLENGES.pop(chal.get("id"), None)
    return jsonify({"ok": True, "username": username})


def logout():
    u = current_user()
    if u:
        # Make the node disappear from LIVE pool immediately after logout.
        try:
            uid = current_user_id()
            set_contrib_offline(BASE_DIR, uid)
        except Exception:
            pass
        try:
            clear_ram_user(u)
        except Exception:
            pass
    session.clear()
    return redirect(url_for("system_routes.home"))


@require_login
def account():
    """Account settings: optional device binding."""
    me = current_user()
    user = get_user_by_username(BASE_DIR, me) or {}
    device_identity = None
    if SIGNER_MODE == 'FIRMWARE':
        try:
            device_identity = verify_device_hello(device_hello_via_firmware()).__dict__
        except Exception:
            device_identity = {"ok": False}

    if request.method == "POST":
        req = 1 if (request.form.get("require_device") == "on") else 0
        action = request.form.get("action") or "save"
        fp = user.get("device_fingerprint")

        if action == "bind":
            if SIGNER_MODE != 'FIRMWARE':
                flash("Przypisanie wymaga trybu firmware.")
            else:
                try:
                    di = verify_device_hello(device_hello_via_firmware())
                    if not di.ok:
                        flash("Nie wykryto urządzenia.")
                    else:
                        fp = di.fingerprint
                        flash("Urządzenie przypisane.")
                except Exception:
                    flash("Nie udało się odczytać fingerprintu.")

        set_device_binding(BASE_DIR, me, bool(req), fp)
        user = get_user_by_username(BASE_DIR, me) or user

    return render_template(
        "account.html",
        me=me,
        require_device=int(user.get("require_device") or 0),
        device_fingerprint=user.get("device_fingerprint"),
        device_identity=device_identity,
        signer_mode=SIGNER_MODE,
    )


@require_login
def account_preferences():
    """Persist feed/UI preferences to the user profile.

    Stored fields (v1):
      - mode: "13"|"21"
      - topics: list[str]  (community IDs)
      - palette: str
      - theme: "dark"|"light"
    """
    me = current_user()
    user = get_user_by_username(BASE_DIR, me) or {}
    user_id = int(user.get("id") or 0)
    if not user_id:
        return jsonify({"ok": False, "error": "user_not_found"}), 404

    if request.method == "GET":
        prefs = get_user_preferences(BASE_DIR, user_id)
        return jsonify({"ok": True, "preferences": prefs})

    # POST
    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or "").strip() or "13"
    palette = (data.get("palette") or "").strip() or "neo"
    theme = (data.get("theme") or "").strip() or "dark"
    topics = data.get("topics") or []
    lang = (data.get("lang") or "").strip() or (request.args.get("lang") or "").strip()
    if not isinstance(topics, list):
        topics = []
    topics = [str(x).strip() for x in topics if str(x).strip()]

    if lang not in LANGS:
        lang = "pl"
    prefs = {
        "mode": mode if mode in ("13", "21") else "13",
        "palette": palette,
        "theme": theme if theme in ("dark", "light") else "dark",
        "lang": lang,
        "topics": topics,
        "updated_at": time.time(),
    }
    set_user_preferences(BASE_DIR, user_id, prefs)

    # Optional: log to event chain via rounds (defense: profile changes visible)
    try:
        add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {"type": "USER_PREFERENCES", "author": me, "payload": {"mode": prefs["mode"], "palette": prefs["palette"], "theme": prefs["theme"], "lang": prefs["lang"], "topics": prefs["topics"]}, "ts": prefs["updated_at"]},
        )
    except Exception:
        pass

    return jsonify({"ok": True, "preferences": prefs})



@require_login
def timeline():
    return render_template("timeline.html", me=current_user())

def feed():
    # Mode: legacy 13 vs 21. In practice we default to 21 (simpler UX).
    mode = (request.args.get("mode") or "").strip()
    me = current_user()
    contrib = None
    if me:
        try:
            contrib = get_contrib_settings(BASE_DIR, current_user_id())
        except Exception:
            contrib = None
    palette = (request.args.get("palette") or "").strip()
    theme = (request.args.get("theme") or "").strip()
    lang = (request.args.get("lang") or "").strip()

    communities_13 = [
        {"id": "ma",       "name": "MA – Społeczność"},
        {"id": "tech",     "name": "Technologia & AI"},
        {"id": "science",  "name": "Nauka"},
        {"id": "philo",    "name": "Filozofia"},
        {"id": "psyche",   "name": "Psychologia"},
        {"id": "spirit",   "name": "Duchowość"},
        {"id": "nature",   "name": "Natura"},
        {"id": "travel",   "name": "Podróże"},
        {"id": "art",      "name": "Sztuka"},
        {"id": "music",    "name": "Muzyka"},
        {"id": "business", "name": "Biznes"},
        {"id": "finance",  "name": "Finanse"},
        {"id": "fun",      "name": "Humor & lekkość"},
    ]

    communities_21 = communities_13 + [
        {"id": "lifestyle", "name": "Lifestyle"},
        {"id": "relations", "name": "Relacje"},
        {"id": "motivation","name": "Motywacja"},
        {"id": "edu",       "name": "Edukacja & rozwój"},
        {"id": "gaming",    "name": "Gaming"},
        {"id": "food",      "name": "Kulinaria"},
        {"id": "animals",   "name": "Zwierzęta"},
        {"id": "global",    "name": "Global"},
    ]

    all_posts = _decorate_posts(load_posts())

    # If user is logged in and did not provide explicit mode/filters, use saved preferences.
    selected = request.args.getlist("c")
    if me and (not mode or (mode not in ("13", "21"))) and not request.args.get("mode"):
        try:
            user = get_user_by_username(BASE_DIR, me) or {}
            prefs = get_user_preferences(BASE_DIR, int(user.get("id") or 0))
            saved_mode = (prefs.get("mode") or "").strip()
            if saved_mode in ("13", "21"):
                mode = saved_mode
        except Exception:
            pass

    # Hard default: 21 (so Feed never blocks the user on the mode chooser screen).
    if mode not in ("13", "21"):
        mode = "21"

    if mode == "13":
        communities = communities_13
    else:
        communities = communities_21

    # If user is logged in and did not provide explicit filters, use saved preferences.
    if me and not selected:
        try:
            user = get_user_by_username(BASE_DIR, me) or {}
            prefs = get_user_preferences(BASE_DIR, int(user.get("id") or 0))
            saved_mode = (prefs.get("mode") or "").strip()
            saved_topics = prefs.get("topics") or []
            if saved_mode in ("13", "21") and not request.args.get("mode"):
                mode = saved_mode
            if isinstance(saved_topics, list) and saved_topics:
                selected = [str(x) for x in saved_topics]
            if not palette:
                palette = (prefs.get("palette") or "").strip()
            if not theme:
                theme = (prefs.get("theme") or "").strip()
            if not lang:
                lang = (prefs.get("lang") or "").strip()
        except Exception:
            pass

    if not palette:
        palette = "neo"
    if theme not in ("dark", "light"):
        theme = "dark"
    if lang not in LANGS:
        lang = getattr(g, "ui_lang", "pl")
    valid_ids = {c["id"] for c in communities}

    if not selected:
        filtered_posts = [p for p in all_posts if p.get("community") in valid_ids]
    else:
        filtered_posts = [p for p in all_posts if p.get("community") in selected]

    # UX safety: always show your own posts even if your filters don't include that community.
    if me:
        mine = [p for p in all_posts if (p.get("author") == me)]
        # keep ordering (newest first) while de-duping
        seen = set()
        merged = []
        for p in (mine + filtered_posts):
            pid = (p.get("manifest") or {}).get("id") or p.get("manifest_hash_b64") or id(p)
            if pid in seen:
                continue
            seen.add(pid)
            merged.append(p)
        filtered_posts = merged

    return render_template(
        "feed.html",
        mode=mode,
        me=me,
        contrib=contrib,
        communities=communities,
        selected=selected,
        palette=palette,
        theme=theme,
        posts=filtered_posts,
        lang=lang,
    )


@require_login
def feed_attach():
    """Upload a file, chunk it into the local blobstore, return chunk list for embedding in a post.

    This does NOT create a media-manifest yet (v0). The caller will embed returned
    chunk list directly in the signed post manifest.
    """
    me = current_user() or ""
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "missing_file"}), 400

    f = request.files["file"]
    filename = (getattr(f, "filename", "") or "").strip() or "upload.bin"
    mime = (getattr(f, "mimetype", "") or "").strip() or "application/octet-stream"

    try:
        chunk_size = int(request.form.get("chunk_size") or (1024 * 1024))
    except Exception:
        chunk_size = 1024 * 1024
    chunk_size = max(256 * 1024, min(chunk_size, 8 * 1024 * 1024))

    # Safety limit for prototype
    max_bytes = 512 * 1024 * 1024  # 512MB

    os.makedirs(BLOB_DIR, exist_ok=True)
    try:
        refs = chunk_and_store(f.stream, BLOB_DIR, chunk_size=chunk_size, max_bytes=max_bytes)
    except Exception as e:
        return jsonify({"ok": False, "error": f"chunk_failed:{e.__class__.__name__}"}), 500

    chunks = [r.sha256_hex for r in refs]
    total_size = int(sum(r.size for r in refs))
    file_id = uuid.uuid4().hex

    attachment = {
        "file_id": file_id,
        "filename": filename,
        "mime": mime,
        "size": total_size,
        "chunk_size": chunk_size,
        "chunks": chunks,
        "v": 1,
    }

    # Optional audit event
    try:
        add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {"type": "FEED_ATTACHMENT", "author": me, "file_id": file_id, "mime": mime, "size": total_size, "chunks": len(chunks), "ts": time.time()},
        )
    except Exception:
        pass

    return jsonify({"ok": True, "attachment": attachment})


@require_login
def feed_create():
    """Create a new feed post as a signed manifest (purpose=FID_POST)."""
    me = current_user() or ""
    community = (request.form.get("community") or "").strip()
    text = (request.form.get("text") or "").strip()
    mode = (request.form.get("mode") or "").strip() or "21"
    palette = (request.form.get("palette") or "").strip() or "neo"
    theme = (request.form.get("theme") or "").strip() or "dark"
    attachments_json = (request.form.get("attachments_json") or "").strip()

    if not community:
        flash("Wybierz społeczność.")
        return redirect(url_for("feed.feed_route", mode=mode, palette=palette, theme=theme))
    if not text:
        flash("Treść posta jest wymagana.")
        return redirect(url_for("feed.feed_route", mode=mode, palette=palette, theme=theme))

    # Optional anti-spam gate: require bound device for posting
    try:
        user = get_user_by_username(BASE_DIR, me)
        require_dev = int((user or {}).get("require_device") or 0)
        fp = (user or {}).get("device_fingerprint")
    except Exception:
        require_dev = 0
        fp = None
    if require_dev and not fp:
        flash("To konto wymaga przypisanego urządzenia do publikacji (brak fingerprintu).")
        return redirect(url_for("account_routes.account_route"))

    post_id = uuid.uuid4().hex
    ts = time.time()

    attachments = []
    if attachments_json:
        try:
            maybe = json.loads(attachments_json)
            if isinstance(maybe, list):
                attachments = maybe
        except Exception:
            attachments = []

    manifest = {
        "id": post_id,
        "author": me,
        "community": community,
        "text": text,
        "attachments": attachments,
        "timestamp": ts,
        "v": 2,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    manifest_hash_b64 = _sha256_b64(manifest_bytes)

    purpose = "FID_POST"
    sig_b64 = None
    firmware_meta = None
    if SIGNER_MODE == "FIRMWARE":
        # monotonic counter per sender
        state = load_state(BASE_DIR)
        state.setdefault("meta", {}).setdefault("sign_counters", {})
        last = int(state["meta"]["sign_counters"].get(me, 0))
        nxt = last + 1
        state["meta"]["sign_counters"][me] = nxt
        _save_json(os.path.join(DATA_DIR, "wallet_state.json"), state)
        firmware_meta = {"counter": nxt}
        resp = sign_hash_via_firmware(purpose, manifest_hash_b64, me, meta=firmware_meta)
        sig_b64 = (resp or {}).get("sig_b64")
    else:
        sig_b64 = sign_hash(manifest_hash_b64, me, purpose=purpose)

    if not sig_b64:
        flash("Nie udało się podpisać posta.")
        return redirect(url_for("feed.feed_route", mode=mode))

    if not verify_hash(manifest_hash_b64, sig_b64, me, purpose=purpose):
        flash("Podpis posta nie przeszedł weryfikacji.")
        return redirect(url_for("feed.feed_route", mode=mode))

    post_obj = {
        "author": me,
        "community": community,
        "text": text,
        "timestamp": ts,
        "minutes_ago": 0,
        "manifest": manifest,
        "manifest_hash_b64": manifest_hash_b64,
        "signature_b64": sig_b64,
        "purpose": purpose,
        "attachments": attachments,
    }

    posts = load_posts()
    if not isinstance(posts, list):
        posts = []
    posts.insert(0, post_obj)
    posts = posts[:500]
    save_posts(posts)

    # Add event to Horizon rounds buffer
    try:
        _st, committed = add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {
                "type": "FEED_POST",
                "post_id": post_id,
                "manifest_hash_b64": manifest_hash_b64,
                "author": me,
                "community": community,
                "timestamp": ts,
                "attachments": attachments,
            },
        )
        if committed:
            save_horizon_receipt(BASE_DIR, "FEED_POST", manifest_hash_b64, json.dumps(committed))
    except Exception:
        pass

    flash("Post opublikowany (podpis zweryfikowany).")
    return redirect(url_for("feed.feed_route", mode=mode, palette=palette, theme=theme))


def media_index():
    """Public index of signed media manifests (no actual file hosting yet)."""
    me = current_user()
    items = _decorate_media(load_media())
    items.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return render_template("media.html", me=me, items=items)


@require_login
def media_new():
    return render_template("media_new.html", me=current_user())


@require_login
def storage_index():
    """Local chunking tool (prototype).

    Upload a file, split into chunks, store in local blobstore, and return a list
    of chunk hashes that can be pasted into a media manifest.
    """
    return render_template("storage.html", me=current_user(), chunk_size_mb=1)


@require_login
def storage_upload():
    me = current_user() or ""
    f = request.files.get("file")
    if not f:
        flash("Nie wybrano pliku.")
        return redirect(url_for("market_storage.storage_index"))

    # Prototype limits (avoid accidental huge uploads)
    try:
        chunk_size_mb = float(request.form.get("chunk_size_mb") or "1")
    except ValueError:
        chunk_size_mb = 1.0
    chunk_size = int(max(0.25, min(8.0, chunk_size_mb)) * 1024 * 1024)

    max_mb = float(os.getenv("MA_STORAGE_MAX_UPLOAD_MB", "256"))
    max_bytes = int(max(8, min(2048, max_mb)) * 1024 * 1024)

    # Stream into blobstore
    chunks = chunk_and_store(f.stream, BLOB_DIR, chunk_size=chunk_size, max_bytes=max_bytes)
    if not chunks:
        flash("Nie udało się pociąć pliku (pusty plik?).")
        return redirect(url_for("market_storage.storage_index"))

    file_id = uuid.uuid4().hex
    ts = time.time()
    total = sum(c.size for c in chunks)
    chunk_ids = [c.sha256_hex for c in chunks]

    # Save a small local record for convenience
    uploads_file = os.path.join(DATA_DIR, "storage_uploads.json")
    uploads = _load_json(uploads_file, [])
    if not isinstance(uploads, list):
        uploads = []
    uploads.insert(0, {
        "id": file_id,
        "user": me,
        "filename": getattr(f, "filename", "") or "",
        "mime": getattr(f, "mimetype", "") or "",
        "chunk_size": chunk_size,
        "chunks": chunk_ids,
        "total_bytes": total,
        "timestamp": ts,
    })
    uploads = uploads[:200]
    _save_json(uploads_file, uploads)

    # Log to event chain (as a local tooling event)
    try:
        add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {
                "type": "STORAGE_CHUNKED",
                "file_id": file_id,
                "filename": getattr(f, "filename", "") or "",
                "total_bytes": total,
                "chunk_count": len(chunk_ids),
                "first_chunk": chunk_ids[0],
                "timestamp": ts,
                "user": me,
            },
        )
    except Exception:
        pass

    return render_template(
        "storage_result.html",
        me=me,
        file_id=file_id,
        filename=getattr(f, "filename", "") or "",
        total_bytes=total,
        chunk_size=chunk_size,
        chunks=chunks,
        chunk_ids_text="\n".join(chunk_ids),
    )


def storage_chunk(sha256_hex: str):
    """Serve a chunk from the local blobstore (prototype 'peer serve')."""
    try:
        _ensure_chunk(sha256_hex)
        path = open_chunk(BLOB_DIR, sha256_hex)
    except FileNotFoundError:
        return ("chunk_not_found", 404)
    return send_file(path, mimetype="application/octet-stream", as_attachment=False)


def api_chain_head():
    """Return local event chain head info for peer sync."""
    try:
        # Lightweight head: state seq + last hash from verify_full_chain or state.
        st = verify_full_chain(log_dir=Path(DATA_DIR))
        return jsonify({"ok": True, "head": {"seq": int(st.get("state_seq") or 0), "last_hash": str(st.get("state_last_hash") or "")}})
    except Exception:
        # Fallback
        try:
            state_path = Path(DATA_DIR) / "event_chain_state.json"
            if state_path.exists():
                obj = json.loads(state_path.read_text(encoding="utf-8"))
                return jsonify({"ok": True, "head": {"seq": int(obj.get("seq") or 0), "last_hash": str(obj.get("last_hash") or "")}})
        except Exception:
            pass
        return jsonify({"ok": False, "reason": "no_state"})


def api_chain_events():
    """Export a slice of the event chain.

    Query params:
      from_seq (default 1)
      limit (default 2000, max 50000)
    """
    try:
        from_seq = int(request.args.get("from_seq") or 1)
        limit = int(request.args.get("limit") or 2000)
    except Exception:
        return jsonify({"ok": False, "reason": "bad_params"}), 400

    bundle = export_events(log_dir=Path(DATA_DIR), from_seq=from_seq, limit=limit)
    return jsonify(bundle)


@require_login
def api_chain_import():
    """Import raw events (prototype). Intended for local tooling."""
    # Safety gate: allow import only from localhost by default.
    # Set MA_ALLOW_CHAIN_IMPORT=1 to allow remote import for trusted admin sessions.
    allow_remote = str(os.getenv("MA_ALLOW_CHAIN_IMPORT") or "").strip() == "1"
    remote = request.remote_addr or ""
    if not allow_remote and remote not in ("127.0.0.1", "::1"):
        return jsonify({"ok": False, "reason": "forbidden"}), 403

    try:
        body = request.get_json(force=True, silent=True) or {}
        events = body.get("events")
        if not isinstance(events, list):
            return jsonify({"ok": False, "reason": "no_events"}), 400
        res = import_events(log_dir=Path(DATA_DIR), events=events)
        return jsonify(res), (200 if res.get("ok") else 400)
    except Exception:
        return jsonify({"ok": False, "reason": "bad_request"}), 400


@require_login
def storage_assemble_index():
    """Create an assembly (virtual file) from a list of chunk hashes."""
    me = current_user() or ""
    uploads_file = os.path.join(DATA_DIR, "storage_uploads.json")
    uploads = _load_json(uploads_file, [])
    if not isinstance(uploads, list):
        uploads = []
    uploads = [u for u in uploads if (u.get("user") == me)][:25]
    return render_template("storage_assemble.html", me=me, uploads=uploads)


@require_login
def storage_assemble_create():
    me = current_user() or ""
    chunks_raw = (request.form.get("chunks") or "").strip()
    filename = (request.form.get("filename") or "").strip() or "assembled.bin"
    mime = (request.form.get("mime") or "").strip() or "application/octet-stream"

    try:
        chunks = parse_chunk_list(chunks_raw)
    except Exception:
        flash("Nieprawidłowa lista chunków (SHA256 hex, po jednym na linię).")
        return redirect(url_for("market_storage.storage_assemble_index"))

    if not chunks:
        flash("Wklej listę chunków.")
        return redirect(url_for("market_storage.storage_assemble_index"))

    assembly_id = compute_assembly_id(chunks)
    assemblies_dir = os.path.join(BLOB_DIR, "assemblies")

    try:
        total_bytes = estimate_total_bytes(BLOB_DIR, chunks, ensure_chunk=_ensure_chunk)
    except FileNotFoundError:
        flash("Brakuje jednego lub więcej chunków w blobstore.")
        return redirect(url_for("market_storage.storage_assemble_index"))

    ts = time.time()
    save_assembly(
        assemblies_dir,
        assembly_id=assembly_id,
        filename=filename,
        mime=mime,
        chunks=chunks,
        created_at=ts,
        total_bytes=total_bytes,
    )

    # Pin chunks belonging to an assembly so cache eviction won't break it.
    try:
        _add_pins(PINS_FILE, chunks)
    except Exception:
        pass

    # Event chain
    try:
        add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {
                "type": "STORAGE_ASSEMBLY_CREATED",
                "assembly_id": assembly_id,
                "filename": filename,
                "mime": mime,
                "total_bytes": total_bytes,
                "chunk_count": len(chunks),
                "timestamp": ts,
                "user": me,
            },
        )
    except Exception:
        pass

    return redirect(url_for("market_storage.storage_assemble_view", assembly_id=assembly_id))


@require_login
def storage_assemble_view(assembly_id: str):
    me = current_user() or ""
    assemblies_dir = os.path.join(BLOB_DIR, "assemblies")
    try:
        a = load_assembly(assemblies_dir, assembly_id)
    except Exception:
        return ("assembly_not_found", 404)

    # Small preview hint for UI
    is_video = (a.mime or "").startswith("video/")
    is_audio = (a.mime or "").startswith("audio/")
    return render_template(
        "storage_preview.html",
        me=me,
        a=a,
        is_video=is_video,
        is_audio=is_audio,
    )


def storage_stream(assembly_id: str):
    """Stream an assembled file from chunk list.

    Supports basic byte ranges for media playback.
    """
    assemblies_dir = os.path.join(BLOB_DIR, "assemblies")
    try:
        a = load_assembly(assemblies_dir, assembly_id)
    except Exception:
        return ("assembly_not_found", 404)

    total = int(a.total_bytes or 0)

    # Parse Range: bytes=start-end
    range_header = request.headers.get("Range")
    start = 0
    end = None
    status = 200
    headers = {
        "Accept-Ranges": "bytes",
        "Content-Type": a.mime or "application/octet-stream",
    }

    if range_header and range_header.startswith("bytes="):
        try:
            part = range_header.split("=", 1)[1].split(",", 1)[0]
            s, e = part.split("-", 1)
            start = int(s) if s else 0
            end = int(e) if e else (total - 1)
            if start < 0:
                start = 0
            if end is not None and end >= total:
                end = total - 1
            if total and start <= end:
                status = 206
                headers["Content-Range"] = f"bytes {start}-{end}/{total}"
                headers["Content-Length"] = str((end - start) + 1)
        except Exception:
            # ignore bad range
            start = 0
            end = None

    if status == 200:
        if total:
            headers["Content-Length"] = str(total)

    def gen():
        yield from iter_assembled_bytes(BLOB_DIR, a.chunks, range_start=start, range_end=end, ensure_chunk=_ensure_chunk)

    return Response(gen(), status=status, headers=headers)


@require_login
def media_create():
    """Create a signed media manifest (purpose=MEDIA_MANIFEST)."""
    me = current_user() or ""
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    cids_raw = (request.form.get("cids") or "").strip()
    mime = (request.form.get("mime") or "").strip() or "video/mp4"
    visibility = (request.form.get("visibility") or "public").strip()

    if not title:
        flash("Tytuł jest wymagany.")
        return redirect(url_for("system_routes.media_new"))
    if not cids_raw:
        flash("Wklej listę CID/hash chunków (min. 1).")
        return redirect(url_for("system_routes.media_new"))

    cids = [c.strip() for c in cids_raw.replace("\r", "").split("\n") if c.strip()]
    if not cids:
        flash("Nie znaleziono żadnego CID/hash.")
        return redirect(url_for("system_routes.media_new"))

    media_id = uuid.uuid4().hex
    ts = time.time()

    manifest = {
        "id": media_id,
        "author": me,
        "title": title,
        "description": description,
        "mime": mime,
        "visibility": visibility,
        "chunks": cids,
        "timestamp": ts,
        "v": 1,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    manifest_hash_b64 = _sha256_b64(manifest_bytes)

    purpose = "MEDIA_MANIFEST"
    sig_b64 = None
    if SIGNER_MODE == "FIRMWARE":
        state = load_state(BASE_DIR)
        state.setdefault("meta", {}).setdefault("sign_counters", {})
        last = int(state["meta"]["sign_counters"].get(me, 0))
        nxt = last + 1
        state["meta"]["sign_counters"][me] = nxt
        _save_json(os.path.join(DATA_DIR, "wallet_state.json"), state)
        resp = sign_hash_via_firmware(purpose, manifest_hash_b64, me, meta={"counter": nxt})
        sig_b64 = (resp or {}).get("sig_b64")
    else:
        sig_b64 = sign_hash(manifest_hash_b64, me, purpose=purpose)

    if not sig_b64:
        flash("Nie udało się podpisać manifestu.")
        return redirect(url_for("system_routes.media_new"))
    if not verify_hash(manifest_hash_b64, sig_b64, me, purpose=purpose):
        flash("Podpis manifestu nie przeszedł weryfikacji.")
        return redirect(url_for("system_routes.media_new"))

    obj = {
        "id": media_id,
        "author": me,
        "timestamp": ts,
        "manifest": manifest,
        "manifest_hash_b64": manifest_hash_b64,
        "signature_b64": sig_b64,
        "purpose": purpose,
    }

    items = load_media()
    if not isinstance(items, list):
        items = []
    items.insert(0, obj)
    items = items[:500]
    save_media(items)

    # Event chain / rounds
    try:
        _st, committed = add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {
                "type": "MEDIA_MANIFEST",
                "media_id": media_id,
                "manifest_hash_b64": manifest_hash_b64,
                "author": me,
                "timestamp": ts,
            },
        )
        if committed:
            save_horizon_receipt(BASE_DIR, "MEDIA_MANIFEST", manifest_hash_b64, json.dumps(committed))
    except Exception:
        pass

    flash("Manifest dodany (podpis zweryfikowany).")
    return redirect(url_for("system_routes.media_index"))


def market():
    me = current_user()
    palette = (request.args.get("palette") or "").strip()
    theme = (request.args.get("theme") or "").strip()
    lang = (request.args.get("lang") or "").strip()
    contrib = None
    listings = list_market_listings(BASE_DIR, status=None, limit=200)
    purchases = []
    jobs = []
    if me:
        purchases = list_market_purchases_for_user(BASE_DIR, me, limit=200)
        jobs = list_compute_jobs_for_user(BASE_DIR, me, limit=50)
        try:
            contrib = get_contrib_settings(BASE_DIR, current_user_id())
        except Exception:
            contrib = None

        # Pull UI preferences (best-effort) so Market/Comm match Feed.
        try:
            user = get_user_by_username(BASE_DIR, me) or {}
            prefs = get_user_preferences(BASE_DIR, int(user.get("id") or 0))
            if not palette:
                palette = (prefs.get("palette") or "").strip()
            if not theme:
                theme = (prefs.get("theme") or "").strip()
            if not lang:
                lang = (prefs.get("lang") or "").strip()
        except Exception:
            pass

    if not palette:
        palette = "neo"
    if theme not in ("dark", "light"):
        theme = "dark"
    if lang not in LANGS:
        lang = getattr(g, "ui_lang", "pl")

    # --- Live pools (prototype) ------------------------------------------------
    # In v0.1 we treat compute/storage pools as "market-visible capabilities".
    # DB is the fast view; Event Chain keeps audit trail.
    # Pool visibility should be "LIVE". Use short TTL so offline nodes disappear quickly.
    compute_nodes = list_active_compute_offers(BASE_DIR, ttl_sec=120, base_mem_mb=256)
    declared_mem = sum(int(n.get("declared_mem_mb") or 0) for n in compute_nodes)
    # Safety: only half is considered usable at any moment (disconnect reserve).
    usable_mem = int(declared_mem * 0.5)

    storage_fields = list_active_storage_offers(BASE_DIR, ttl_sec=120)
    declared_storage_gb = sum(int(f.get("gb") or 0) for f in storage_fields)
    # Keep usable capacity visible even for small pools (e.g. 1 GB -> 0.5 GB).
    usable_storage_gb = round(float(declared_storage_gb) * 0.5, 1)

    pool = {
        "compute": {
            "nodes": compute_nodes,
            "declared_mem_mb": declared_mem,
            "usable_mem_mb": usable_mem,
        },
        "storage": {
            "fields": storage_fields,
            "declared_gb": declared_storage_gb,
            "usable_gb": usable_storage_gb,
        },
    }
    return render_template(
        "market.html",
        me=me,
        contrib=contrib,
        listings=listings,
        purchases=purchases,
        jobs=jobs,
        pool=pool,
        palette=palette,
        theme=theme,
        lang=lang,
    )


def api_pool_status():
    compute_nodes = list_active_compute_offers(BASE_DIR, ttl_sec=120, base_mem_mb=256)
    declared_mem = sum(int(n.get("declared_mem_mb") or 0) for n in compute_nodes)
    usable_mem = int(declared_mem * 0.5)
    storage_fields = list_active_storage_offers(BASE_DIR, ttl_sec=120)
    declared_storage_gb = sum(int(f.get("gb") or 0) for f in storage_fields)
    usable_storage_gb = round(float(declared_storage_gb) * 0.5, 1)
    return jsonify(
        {
            "ok": True,
            "compute": {
                "nodes": compute_nodes,
                "declared_mem_mb": declared_mem,
                "usable_mem_mb": usable_mem,
            },
            "storage": {
                "fields": storage_fields,
                "declared_gb": declared_storage_gb,
                "usable_gb": usable_storage_gb,
            },
        }
    )


@require_login
def api_pool_ping():
    """Keep this user visible in pools (best-effort heartbeat)."""
    uid = current_user_id()
    st = touch_contrib(BASE_DIR, uid)
    return jsonify({"ok": True, "contrib": st})


@require_login
def market_create():
    me = current_user() or ""
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    price_raw = (request.form.get("price") or "0").strip()
    bg_mode = (request.form.get("bg_mode") or "auto").strip()

    try:
        price = float(price_raw)
    except ValueError:
        price = 0.0

    if not title:
        flash("Tytuł jest wymagany.")
        return redirect(url_for("market_storage.market"))
    if price <= 0:
        flash("Cena musi być większa od zera.")
        return redirect(url_for("market_storage.market"))

    listing_id = str(uuid.uuid4())
    create_market_listing(
        BASE_DIR,
        listing_id=listing_id,
        seller=me,
        title=title,
        description=description,
        price=price,
        currency="LC",
        status="ACTIVE",
        owner=None,
        asset_id=None,
        media_dir=None,
        thumb_path=None,
    )

    # optional photo processing
    f = request.files.get("photo")
    if f and f.filename:
        try:
            # store under data/market_media/<listing_id>/
            rel_dir = os.path.join("market_media", listing_id)
            abs_dir = os.path.join(PUBLIC_MEDIA_DIR, rel_dir)
            os.makedirs(abs_dir, exist_ok=True)
            raw_bytes = f.read()
            raw_path = os.path.join(abs_dir, "raw_upload")
            with open(raw_path, "wb") as out:
                out.write(raw_bytes)

            processed = process_product_photos(raw_bytes, studio_mode=bg_mode)
            cutout_path = os.path.join(abs_dir, "cutout.png")
            studio_path = os.path.join(abs_dir, "studio.png")
            with open(cutout_path, "wb") as out:
                out.write(processed.cutout_png)
            with open(studio_path, "wb") as out:
                out.write(processed.studio_png)

            # update listing pointers
            update_listing_media(BASE_DIR, listing_id, media_dir=rel_dir, thumb_path=os.path.join(rel_dir, "studio.png"))
        except Exception:
            # never block listing creation
            pass

    flash("Dodano ofertę.")
    return redirect(url_for("market_storage.market"))



def api_pricing():
    if request.method == 'POST':
        state = _tick_compute_pricing()
    else:
        state = get_pricing_state(BASE_DIR, 'compute')
        if not state or not state.get('multiplier'):
            state = _tick_compute_pricing()
    mult = float(state.get('multiplier') or 1.0)
    return jsonify({
        'compute': {
            'base_cost_units': COMPUTE_BASE_COST_UNITS,
            'multiplier': mult,
            'effective_cost_units': COMPUTE_BASE_COST_UNITS * mult,
            'inputs': state.get('inputs') if isinstance(state, dict) else None
        }
    })


def _wallet_transfer_internal(sender: str, receiver: str, amount: float, description: str, *, allow_firmware_for_sender: bool = False) -> dict:
    from services.settlement_service import wallet_transfer_internal
    return wallet_transfer_internal(
        sender=sender,
        receiver=receiver,
        amount=amount,
        description=description,
        allow_firmware_for_sender=allow_firmware_for_sender,
        load_state=load_state,
        ensure_account=ensure_account,
        ensure_user_wallet_keypair=ensure_user_wallet_keypair,
        wallet_keys_dir=WALLET_KEYS_DIR,
        evaluate_transaction=evaluate_transaction,
        apply_transaction=apply_transaction,
        current_user=current_user,
        signer_mode=SIGNER_MODE,
        sign_transaction_via_firmware=sign_transaction_via_firmware,
        sign_transaction=sign_transaction,
        sign_horizon_receipt=sign_horizon_receipt,
        rounds_state_file=ROUNDS_STATE_FILE,
        rounds_file=ROUNDS_FILE,
        horizon_master_keys_dir=HORIZON_MASTER_KEYS_DIR,
        add_event_to_round=add_event_to_round,
    )


@require_login
def compute_create():
    """Create a compute job request (prototype).

    In later versions, this will be broadcast to the pool and executed by remote nodes.
    For now we just record the request and store the input file.
    """
    me = current_user() or ""
    kind = (request.form.get("kind") or "").strip() or "render_stub"
    f = request.files.get("job_file")
    if not f or not getattr(f, "filename", ""):
        flash("Brak pliku do przetworzenia.")
        return redirect(url_for("market_storage.market"))

    job_id = str(uuid.uuid4())
    data_dir = PUBLIC_MEDIA_DIR
    # Create under PUBLIC_MEDIA_DIR, reject symlink escapes.
    _ = safe_mkdirs(Path(data_dir), "compute_jobs")

    # Keep filename safe.
    ext = os.path.splitext(f.filename)[1].lower()[:10]
    if ext and not ext.replace(".", "").isalnum():
        ext = ""
    relpath = os.path.join("compute_jobs", f"{job_id}{ext}")
    try:
        abspath = str(safe_resolve_file(Path(data_dir), relpath))
        f.save(abspath)
    except UnsafePath:
        flash("Błędna ścieżka pliku (bezpieczeństwo).")
        return redirect(url_for("market_storage.market"))

    now = time.time()

    pricing = _tick_compute_pricing()
    price_multiplier = float(pricing.get('multiplier') or 1.0)
    cost_units = float(COMPUTE_BASE_COST_UNITS) * price_multiplier
    pricing_inputs_json = json.dumps(pricing.get('inputs') or {})

    # --- LifeCoin: escrow deposit (payer -> escrow) -------------------
    # Charge the requester immediately so payment & reward cannot drift apart.
    escrow_amount = float(cost_units)
    ensure_account(ESCROW_ACCOUNT, initial=0.0)
    escrow_res = _wallet_transfer_internal(
        me,
        ESCROW_ACCOUNT,
        escrow_amount,
        f"COMPUTE_ESCROW:{job_id}:{kind}",
        allow_firmware_for_sender=True,
    )
    if not escrow_res.get("ok"):
        # cleanup uploaded file
        try:
            if os.path.exists(abspath):
                os.remove(abspath)
        except Exception:
            pass
        flash("Horyzont zablokował płatność (escrow). Sprawdź saldo w portfelu.")
        return redirect(url_for("market_storage.market"))
    try:
        create_compute_job(
            BASE_DIR,
            {
            "id": job_id,
            "owner": me,
            "kind": kind,
            "src_relpath": relpath,
            "status": "QUEUED",
            "created_at": now,
            "updated_at": now,
            "cost_units": cost_units,
            "price_multiplier": price_multiplier,
            "pricing_inputs_json": pricing_inputs_json,
            "escrow_amount": escrow_amount,
            "escrow_status": "HELD",
            "escrow_tx_id": (escrow_res.get("tx") or {}).get("id"),
            "result_relpath": None,
            },
        )
    except Exception:
        # If DB insert fails, refund escrow best-effort.
        try:
            _wallet_transfer_internal(ESCROW_ACCOUNT, me, escrow_amount, f"COMPUTE_REFUND_DBFAIL:{job_id}")
        except Exception:
            pass
        flash("Błąd zapisu joba. Zwrot escrow (best-effort).")
        return redirect(url_for("market_storage.market"))

    flash(f"Job dodany do kolejki. Pobrano {escrow_amount:.3f} LC do escrow.")
    return redirect(url_for("market_storage.market"))



@require_login
def api_compute_job_cancel():
    """Cancel a compute job.

    - QUEUED / unclaimed -> immediate CANCELED + escrow refund
    - WORKING / claimed   -> mark CANCEL_REQUESTED (worker will honor it)
    """
    me = current_user() or ""
    data = request.get_json(silent=True) or {}
    job_id = (data.get("job_id") or "").strip()
    if not job_id:
        return jsonify({"ok": False, "error": "missing_job_id"}), 400

    ok = cancel_compute_job(BASE_DIR, job_id=job_id, owner=me)
    job = get_compute_job(BASE_DIR, job_id) or {}
    settlement = None

    if ok and str(job.get("status") or "") == "CANCELED":
        try:
            settlement = _refund_compute_job_escrow_once(job_id, reason="owner_cancel")
        except Exception:
            settlement = {"ok": False, "type": "ERROR"}
        try:
            append_event(
                log_path=Path(DATA_DIR) / "event_chain" / "event_chain.jsonl",
                state_path=Path(DATA_DIR) / "event_chain" / "event_chain_state.json",
                etype="COMPUTE_JOB_CANCELED",
                payload={"job_id": job_id, "owner": me, "why": "owner_cancel"},
            )
            append_event(
                log_path=Path(DATA_DIR) / "event_chain" / "event_chain.jsonl",
                state_path=Path(DATA_DIR) / "event_chain" / "event_chain_state.json",
                etype="JOB_REFUNDED",
                payload={"job_id": job_id, "owner": me, "reason": "owner_cancel", "settlement": settlement},
            )
        except Exception:
            pass

    return jsonify({
        "ok": True,
        "canceled": bool(ok),
        "status": job.get("status"),
        "cancel_requested": int(job.get("cancel_requested") or 0),
        "settlement": settlement,
    })

def _sha256_hex_path(path: str) -> str:
    from services.compute_runtime_service import sha256_hex_path
    return sha256_hex_path(path)


def _sha256_b64_json(obj: dict) -> str:
    from services.compute_runtime_service import sha256_b64_json
    return sha256_b64_json(obj)


def _execute_compute_job_local(job: dict, data_dir: str) -> tuple[str | None, str | None]:
    from services.compute_runtime_service import execute_compute_job_local
    return execute_compute_job_local(job, data_dir=data_dir)


def _settle_compute_job(job: dict, *, outcome_status: str):
    from services.settlement_service import settle_compute_job
    return settle_compute_job(
        base_dir=BASE_DIR,
        job=job,
        outcome_status=outcome_status,
        escrow_account=ESCROW_ACCOUNT,
        treasury_account=TREASURY_ACCOUNT,
        treasury_cut=COMPUTE_TREASURY_CUT,
        get_compute_job=get_compute_job,
        set_compute_job_settlement=set_compute_job_settlement,
        wallet_transfer_internal=_wallet_transfer_internal,
        refund_compute_job_escrow_once=_refund_compute_job_escrow_once,
    )


@require_login
def api_compute_worker_tick():
    """Manual worker tick: claim + execute one job from the global queue."""
    if not _worker_tick_authorized():
        return jsonify({"ok": False, "error": "worker_auth_invalid"}), 403

    me = current_user() or ""
    uid = current_user_id()
    st = get_contrib_settings(BASE_DIR, uid)
    if int(st.get("slider_pos") or 0) <= 0:
        return jsonify({"ok": False, "error": "not_in_pool"}), 400

    job = claim_next_compute_job(BASE_DIR, executor=me, allow_owner=True)
    if not job:
        return jsonify({"ok": True, "claimed": False})

    data_dir = PUBLIC_MEDIA_DIR
    result_rel, result_hash_hex = _execute_compute_job_local(job=job, data_dir=data_dir)

    try:
        fresh = get_compute_job(BASE_DIR, str(job.get("id"))) or {}
    except Exception:
        fresh = {}
    if int(fresh.get("cancel_requested") or 0) == 1 or str(fresh.get("status") or "") == "CANCEL_REQUESTED":
        try:
            if result_rel:
                rp = os.path.join(data_dir, result_rel)
                if os.path.exists(rp):
                    os.remove(rp)
        except Exception:
            pass

        complete_compute_job(
            BASE_DIR,
            job_id=str(job.get("id")),
            status="CANCELED",
            result_relpath=None,
            result_hash_hex=None,
            proof_json=None,
        )

        settlement = None
        try:
            settlement = _refund_compute_job_escrow_once(str(job.get("id")), reason="cancel_during_exec")
        except Exception:
            settlement = {"ok": False, "type": "ERROR"}

        try:
            append_event(
                log_path=Path(DATA_DIR) / "event_chain" / "event_chain.jsonl",
                state_path=Path(DATA_DIR) / "event_chain" / "event_chain_state.json",
                etype="COMPUTE_JOB_CANCELED",
                payload={"job_id": str(job.get("id")), "owner": str(job.get("owner")), "executor": me, "why": "cancel_during_exec"},
            )
            append_event(
                log_path=Path(DATA_DIR) / "event_chain" / "event_chain.jsonl",
                state_path=Path(DATA_DIR) / "event_chain" / "event_chain_state.json",
                etype="JOB_REFUNDED",
                payload={"job_id": str(job.get("id")), "owner": str(job.get("owner")), "reason": "cancel_during_exec", "settlement": settlement},
            )
        except Exception:
            pass
        return jsonify({"ok": True, "claimed": True, "job_id": job.get("id"), "canceled": True, "settlement": settlement})

    proof = {
        "job_id": job.get("id"),
        "owner": job.get("owner"),
        "executor": me,
        "kind": job.get("kind"),
        "result_relpath": result_rel,
        "result_hash_hex": result_hash_hex,
        "ts": time.time(),
    }
    proof_hash_b64 = _sha256_b64_json(proof)

    if SIGNER_MODE == 'FIRMWARE':
        sig_b64 = sign_hash_via_firmware("COMPUTE_PROOF", proof_hash_b64, me).get("sig_b64")
    else:
        sig_b64 = sign_hash(proof_hash_b64, signer=me, purpose="COMPUTE_PROOF")
    proof["proof_hash_b64"] = proof_hash_b64
    proof["sig_b64"] = sig_b64

    tx = {
        "id": str(job.get("id")),
        "sender": me,
        "receiver": str(job.get("owner")),
        "amount": 0.0,
        "description": f"COMPUTE_RESULT:{job.get('kind')}",
        "timestamp": time.time(),
        "meta": {"result_hash_hex": result_hash_hex, "proof_hash_b64": proof_hash_b64},
    }
    decision, verdicts = evaluate_transaction(tx, load_state())

    outcome_status = "DONE" if result_rel and result_hash_hex else "FAILED"
    complete_compute_job(
        BASE_DIR,
        job_id=str(job.get("id")),
        status=outcome_status,
        result_relpath=result_rel,
        result_hash_hex=result_hash_hex,
        proof_json=json.dumps(proof, ensure_ascii=False, separators=(",", ":")),
    )

    settlement = None
    try:
        settlement = _settle_compute_job(job, outcome_status=outcome_status)
    except Exception:
        settlement = {"type": "ERROR"}

    try:
        append_event(
            log_path=Path(DATA_DIR) / "event_chain" / "event_chain.jsonl",
            state_path=Path(DATA_DIR) / "event_chain" / "event_chain_state.json",
            etype="COMPUTE_JOB_RESULT",
            payload={"job_id": str(job.get("id")), "owner": str(job.get("owner")), "executor": me, "status": outcome_status, "result_hash_hex": result_hash_hex},
        )
        if settlement and settlement.get("type") == "REFUND":
            append_event(
                log_path=Path(DATA_DIR) / "event_chain" / "event_chain.jsonl",
                state_path=Path(DATA_DIR) / "event_chain" / "event_chain_state.json",
                etype="JOB_REFUNDED",
                payload={"job_id": str(job.get("id")), "owner": str(job.get("owner")), "reason": outcome_status.lower(), "settlement": settlement},
            )
    except Exception:
        pass

    receipt = {
        "job_id": str(job.get("id")),
        "decision": decision,
        "verdicts": verdicts,
        "proof_hash_b64": proof_hash_b64,
        "result_hash_hex": result_hash_hex,
        "ts": time.time(),
    }
    try:
        sig_b64_receipt = sign_horizon_receipt(receipt)
    except Exception:
        sig_b64_receipt = None
    if sig_b64_receipt:
        receipt["sig_b64"] = sig_b64_receipt
    try:
        save_horizon_receipt(BASE_DIR, str(job.get("id")), json.dumps(receipt, ensure_ascii=False))
    except Exception:
        pass

    return jsonify({"ok": True, "claimed": True, "job_id": job.get("id"), "status": outcome_status, "proof": proof, "receipt": receipt, "settlement": settlement})



@require_login
def api_receipts():
    uid = current_user_id()
    return jsonify({"ok": True, "receipts": list_horizon_receipts(BASE_DIR, uid, limit=50)})
# ============================
# Security: key rotation & recovery (v0.12)
# ============================

@require_login
def account_security_view():
    """Simple security panel: show recovery key status."""
    me = current_user()
    user = get_user_by_username(BASE_DIR, me) or {}
    user_id = int(user.get("id") or 0)
    sec = get_user_security(BASE_DIR, user_id) if user_id else {"recovery_pub_pem": None}
    return render_template("account_security.html", recovery_pub_pem=sec.get("recovery_pub_pem"))


@require_login
def api_account_recovery():
    me = current_user()
    user = get_user_by_username(BASE_DIR, me) or {}
    user_id = int(user.get("id") or 0)
    if not user_id:
        return jsonify({"ok": False, "error": "user_not_found"}), 404

    if request.method == "GET":
        sec = get_user_security(BASE_DIR, user_id)
        return jsonify({"ok": True, "recovery_pub_pem": sec.get("recovery_pub_pem")})

    data = request.get_json(silent=True) or {}
    recovery_pub_pem = (data.get("recovery_pub_pem") or "").strip() or None
    if recovery_pub_pem and "BEGIN PUBLIC KEY" not in recovery_pub_pem:
        return jsonify({"ok": False, "error": "invalid_recovery_pub_pem"}), 400

    set_user_recovery_pub(BASE_DIR, user_id, recovery_pub_pem)
    try:
        add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {"type": "USER_RECOVERY_UPDATED", "user": me, "ts": time.time(), "has_recovery": bool(recovery_pub_pem)},
        )
    except Exception:
        pass
    return jsonify({"ok": True, "has_recovery": bool(recovery_pub_pem)})


@require_login
def api_account_keys_rotate():
    """Rotate wallet keypair for the current user.

    Prototype flow:
      - archive old key files
      - generate new keypair
      - emit KEY_ROTATION event signed by OLD key (purpose KEY_ROTATION)
    """
    me = current_user()

    # Load old pub first (may be empty on first run)
    try:
        old_pub_pem = load_public_key_pem(me).decode("utf-8", errors="ignore")
    except Exception:
        old_pub_pem = ""

    info = rotate_user_keypair(BASE_DIR, me)
    new_pub_pem = info.get("new_pub_pem") or ""

    statement = {
        "type": "KEY_ROTATION",
        "user": me,
        "old_pub_pem": old_pub_pem,
        "new_pub_pem": new_pub_pem,
        "ts": time.time(),
    }
    canonical = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h_b64 = base64.b64encode(hashlib.sha256(canonical).digest()).decode("utf-8")

    rotation_sig_b64 = ""
    if old_pub_pem:
        try:
            rotation_sig_b64 = sign_hash(h_b64, signer=me, purpose="KEY_ROTATION")
        except Exception:
            rotation_sig_b64 = ""

    try:
        add_event_to_round(
            Path(ROUNDS_STATE_FILE),
            Path(ROUNDS_FILE),
            Path(HORIZON_MASTER_KEYS_DIR),
            {
                "type": "KEY_ROTATION",
                "user": me,
                "ts": time.time(),
                **statement,
                "rotation_sig_b64": rotation_sig_b64,
                "archived_dir": info.get("archived_dir"),
            },
        )
    except Exception:
        pass
    return jsonify({"ok": True, "new_pub_pem": new_pub_pem, "archived_dir": info.get("archived_dir")})


# --- Route blueprints (progressive app.py decomposition) ---
from routes.compute import compute_bp
from routes.auth import auth_bp
from routes.feed import feed_bp
from routes.account import account_bp
from routes.market_storage import market_storage_bp
from routes.system import system_bp
app.register_blueprint(compute_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(feed_bp)
app.register_blueprint(account_bp)
app.register_blueprint(market_storage_bp)
app.register_blueprint(system_bp)


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    init_db(BASE_DIR)
    _bootstrap_default_users()
    app.run(debug=bool(int(os.getenv("MA_DEBUG","0"))))