"""
Secure Messenger - Backend
Cryptographic stack:
  - X25519  : ECDH key exchange (ephemeral per-message)
  - HKDF-SHA256 : Key derivation from shared secret
  - Ed25519 : Digital signatures (authentication)
  - AES-256-GCM : Authenticated encryption (confidentiality + integrity)
  - scrypt  : Password-based key encryption for private keys at rest
  - bcrypt  : Password verification
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, json, base64, hashlib
from pathlib import Path
import bcrypt

# --- cryptography library (pip install cryptography bcrypt flask flask-cors) ---
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__, static_folder="static")
CORS(app)

BASE_DIR   = Path.cwd() / "secure_messenger_data"
USERS_DIR  = BASE_DIR / "users"
MSGS_DIR   = BASE_DIR / "messages"
for d in [BASE_DIR, USERS_DIR, MSGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ─────────────────────── helpers ────────────────────────
def b64e(b: bytes) -> str:  return base64.b64encode(b).decode()
def b64d(s: str)  -> bytes: return base64.b64decode(s)

def user_path(u): return USERS_DIR / u.lower()
def user_exists(u): return user_path(u).exists()

# ─────────────────────── key-at-rest helpers ────────────
def _derive_kek(password: str, salt: bytes) -> bytes:
    """scrypt KDF → 32-byte key-encryption key."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

def _encrypt_private_key(priv_bytes: bytes, password: str) -> dict:
    salt  = os.urandom(32)
    kek   = _derive_kek(password, salt)
    nonce = os.urandom(12)
    ct    = AESGCM(kek).encrypt(nonce, priv_bytes, None)
    return {"salt": b64e(salt), "nonce": b64e(nonce), "ct": b64e(ct)}

def _decrypt_private_key(blob: dict, password: str) -> bytes:
    salt  = b64d(blob["salt"])
    kek   = _derive_kek(password, salt)
    nonce = b64d(blob["nonce"])
    ct    = b64d(blob["ct"])
    return AESGCM(kek).decrypt(nonce, ct, None)

# ─────────────────────── user management ────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data     = request.json
    username = data.get("username","").strip().lower()
    password = data.get("password","")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    if user_exists(username):
        return jsonify({"error": "User already exists"}), 409

    ud = user_path(username)
    ud.mkdir()

    # bcrypt password hash
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    (ud / "pw_hash.txt").write_bytes(pw_hash)

    # X25519 DH keypair
    dh_priv  = X25519PrivateKey.generate()
    dh_pub   = dh_priv.public_key()
    dh_priv_bytes = dh_priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    dh_pub_bytes  = dh_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # Ed25519 signing keypair
    sig_priv = Ed25519PrivateKey.generate()
    sig_pub  = sig_priv.public_key()
    sig_priv_bytes = sig_priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    sig_pub_bytes  = sig_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # Encrypt private keys with password-derived KEK
    (ud / "dh_priv.json").write_text(json.dumps(_encrypt_private_key(dh_priv_bytes, password)))
    (ud / "sig_priv.json").write_text(json.dumps(_encrypt_private_key(sig_priv_bytes, password)))

    # Public keys stored plaintext (public directory)
    (ud / "dh_pub.bin").write_bytes(dh_pub_bytes)
    (ud / "sig_pub.bin").write_bytes(sig_pub_bytes)

    return jsonify({
        "success": True,
        "steps": [
            {"step": "Password Hashing",    "detail": f"bcrypt(password, cost=12) → {pw_hash.decode()[:29]}…"},
            {"step": "DH Keypair (X25519)", "detail": f"pub = {b64e(dh_pub_bytes)[:32]}…"},
            {"step": "Signing Keypair (Ed25519)", "detail": f"pub = {b64e(sig_pub_bytes)[:32]}…"},
            {"step": "Private Key Encryption", "detail": "scrypt(password) → KEK → AES-256-GCM wraps both private keys"},
        ]
    })

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json
    username = data.get("username","").strip().lower()
    password = data.get("password","")

    if not user_exists(username):
        return jsonify({"error": "User not found"}), 404

    ud = user_path(username)
    stored = (ud / "pw_hash.txt").read_bytes()
    if not bcrypt.checkpw(password.encode(), stored):
        return jsonify({"error": "Invalid password"}), 401

    # Try decrypting private keys to verify password works
    try:
        blob = json.loads((ud / "dh_priv.json").read_text())
        _decrypt_private_key(blob, password)
    except Exception:
        return jsonify({"error": "Key decryption failed"}), 401

    return jsonify({"success": True, "username": username,
                    "steps": [
                        {"step": "bcrypt.checkpw", "detail": "Constant-time comparison against stored hash"},
                        {"step": "KEK derivation", "detail": "scrypt(password, salt) → 32-byte KEK"},
                        {"step": "Private key unlock", "detail": "AES-256-GCM.decrypt(KEK, encrypted_priv) → raw key bytes"},
                    ]})

@app.route("/api/users", methods=["GET"])
def list_users():
    users = [p.name for p in USERS_DIR.iterdir() if p.is_dir()]
    return jsonify({"users": users})

# ─────────────────────── send message ───────────────────
@app.route("/api/send", methods=["POST"])
def send_message():
    data      = request.json
    sender    = data["sender"].lower()
    recipient = data["recipient"].lower()
    message   = data["message"]
    password  = data["password"]

    if not user_exists(sender) or not user_exists(recipient):
        return jsonify({"error": "Sender or recipient not found"}), 404

    # ── 1. Authenticate sender – unlock signing key ──
    su = user_path(sender)
    sig_blob = json.loads((su / "sig_priv.json").read_text())
    try:
        sig_priv_bytes = _decrypt_private_key(sig_blob, password)
    except Exception:
        return jsonify({"error": "Invalid password"}), 401
    sig_priv = Ed25519PrivateKey.from_private_bytes(sig_priv_bytes)

    # ── 2. ECDH key exchange ──
    # Generate ephemeral X25519 keypair (per-message → forward secrecy)
    eph_priv = X25519PrivateKey.generate()
    eph_pub  = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # Load recipient's static DH public key
    ru = user_path(recipient)
    recip_dh_pub = X25519PublicKey.from_public_bytes((ru / "dh_pub.bin").read_bytes())

    # ECDH: shared_secret = eph_priv × recip_pub
    shared_secret = eph_priv.exchange(recip_dh_pub)

    # ── 3. HKDF key derivation ──
    hkdf_info = f"{sender}:{recipient}".encode()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=hkdf_info, backend=default_backend())
    aes_key = hkdf.derive(shared_secret)

    # ── 4. AES-256-GCM encryption ──
    nonce = os.urandom(12)
    ciphertext_with_tag = AESGCM(aes_key).encrypt(nonce, message.encode(), eph_pub_bytes)  # AAD = eph_pub

    # ── 5. Ed25519 signature (sign ciphertext + ephemeral pub + recipient) ──
    sig_payload = ciphertext_with_tag + eph_pub_bytes + recipient.encode()
    signature   = sig_priv.sign(sig_payload)

    # ── 6. Assemble & save ──
    pkg = {
        "sender":        sender,
        "recipient":     recipient,
        "eph_pub":       b64e(eph_pub_bytes),
        "ciphertext":    b64e(ciphertext_with_tag),
        "nonce":         b64e(nonce),
        "signature":     b64e(signature),
        "algorithm":     "X25519-ECDH + HKDF-SHA256 + AES-256-GCM + Ed25519",
    }
    idx = len(list(MSGS_DIR.glob("*.json")))
    fname = f"msg_{sender}_to_{recipient}_{idx}.json"
    (MSGS_DIR / fname).write_text(json.dumps(pkg, indent=2))

    return jsonify({
        "success": True,
        "steps": [
            {"step": "① Authenticate Sender",
             "detail": f"Unlocked Ed25519 signing key via scrypt(password) + AES-GCM decryption"},
            {"step": "② ECDH Key Exchange (X25519)",
             "detail": f"Ephemeral pub: {b64e(eph_pub_bytes)[:32]}… × Recipient static pub → shared secret"},
            {"step": "③ HKDF-SHA256 Key Derivation",
             "detail": f"HKDF(shared_secret, info='{sender}:{recipient}') → 32-byte AES key"},
            {"step": "④ AES-256-GCM Encryption",
             "detail": f"nonce={b64e(nonce)[:16]}…  |  ciphertext={b64e(ciphertext_with_tag)[:32]}…"},
            {"step": "⑤ Ed25519 Signature",
             "detail": f"sign(ciphertext ‖ eph_pub ‖ recipient) → {b64e(signature)[:32]}…"},
            {"step": "⑥ Saved to disk",
             "detail": f"File: {fname}"},
        ]
    })

# ─────────────────────── receive message ────────────────
@app.route("/api/messages", methods=["POST"])
def get_messages():
    data     = request.json
    username = data["username"].lower()
    password = data["password"]

    if not user_exists(username):
        return jsonify({"error": "User not found"}), 404

    # Unlock recipient DH private key
    ru = user_path(username)
    dh_blob = json.loads((ru / "dh_priv.json").read_text())
    try:
        dh_priv_bytes = _decrypt_private_key(dh_blob, password)
    except Exception:
        return jsonify({"error": "Invalid password"}), 401
    dh_priv = X25519PrivateKey.from_private_bytes(dh_priv_bytes)

    results = []
    for f in MSGS_DIR.glob("*.json"):
        pkg = json.loads(f.read_text())
        if pkg.get("recipient") != username:
            continue

        steps = []
        plaintext    = None
        sig_valid    = None
        error        = None

        try:
            sender = pkg["sender"]
            eph_pub_bytes = b64d(pkg["eph_pub"])
            ciphertext    = b64d(pkg["ciphertext"])
            nonce         = b64d(pkg["nonce"])
            signature     = b64d(pkg["signature"])

            # ── Verify Ed25519 signature ──
            sender_sig_pub = Ed25519PublicKey.from_public_bytes(
                (user_path(sender) / "sig_pub.bin").read_bytes()
            )
            sig_payload = ciphertext + eph_pub_bytes + username.encode()
            try:
                sender_sig_pub.verify(signature, sig_payload)
                sig_valid = True
                steps.append({"step": "① Verify Ed25519 Signature",
                               "detail": f"Sender's public key verified signature over (ciphertext ‖ eph_pub ‖ recipient) ✅"})
            except InvalidSignature:
                sig_valid = False
                steps.append({"step": "① Verify Ed25519 Signature",
                               "detail": "⚠️ Signature INVALID — message may have been tampered or forged"})

            # ── ECDH ──
            eph_pub  = X25519PublicKey.from_public_bytes(eph_pub_bytes)
            shared_secret = dh_priv.exchange(eph_pub)
            steps.append({"step": "② ECDH Key Exchange (X25519)",
                           "detail": f"recip_priv × eph_pub → shared secret (32 bytes, never transmitted)"})

            # ── HKDF ──
            hkdf_info = f"{sender}:{username}".encode()
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=hkdf_info, backend=default_backend())
            aes_key = hkdf.derive(shared_secret)
            steps.append({"step": "③ HKDF-SHA256 Key Derivation",
                           "detail": f"HKDF(shared_secret, info='{sender}:{username}') → 32-byte AES key"})

            # ── AES-256-GCM decrypt ──
            plaintext_bytes = AESGCM(aes_key).decrypt(nonce, ciphertext, eph_pub_bytes)
            plaintext = plaintext_bytes.decode()
            steps.append({"step": "④ AES-256-GCM Decryption",
                           "detail": f"GCM tag verified ✅ — authenticated decryption succeeded"})

        except Exception as e:
            error = str(e)
            steps.append({"step": "Error", "detail": error})

        results.append({
            "filename":  f.name,
            "sender":    pkg.get("sender"),
            "recipient": pkg.get("recipient"),
            "algorithm": pkg.get("algorithm"),
            "plaintext": plaintext,
            "sig_valid": sig_valid,
            "error":     error,
            "steps":     steps,
        })

    return jsonify({"messages": results})

# ─────────────────────── static ─────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
