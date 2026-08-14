#!/usr/bin/env python3
"""
cipher_client.py — End-to-end encrypted messaging client for your
self-hosted Cipher Messaging API (see the `server/` folder — deploy it
free on Render).

Configure with environment variables before running:
    export CIPHER_API_URL="https://<your-service-name>.onrender.com"
    export CIPHER_API_KEY="<the API_KEY you set on the server>"

DESIGN
------
The server only ever stores/relays ciphertext. All cryptography happens
here, client-side:

  * Each user has a P-256 ECDH keypair. The PUBLIC key is published to
    the server (Identity entity). The PRIVATE key never leaves this
    machine (stored under ~/.cipher_messaging/).

  * Every message is encrypted with a fresh, random 256-bit "content
    encryption key" (CEK) using AES-256-GCM.

  * The CEK itself is then "sealed" once per recipient: sender and
    recipient derive a shared secret via ECDH (their static keys),
    stretch it with HKDF-SHA256 into a wrapping key, and AES-GCM-encrypt
    the CEK with that wrapping key. Because ECDH is symmetric
    (priv_A · pub_B == priv_B · pub_A), the recipient can re-derive the
    same wrapping key from their own private key + the sender's public
    key, without any secret ever crossing the wire.

  * A `sender_email` field is stamped on each message (in the clear) so
    recipients know whose public key to use when unsealing. Everything
    else meaningful (the actual text) stays encrypted.

This is a reference implementation for learning / prototyping — not an
audited security product. See the "Limitations" section at the bottom
of this file before using it for anything sensitive.

USAGE
-----
    python3 cipher_client.py register alice@example.com
    python3 cipher_client.py register bob@example.com

    python3 cipher_client.py create-conversation alice@example.com \\
        --with bob@example.com --name "Alice & Bob"

    python3 cipher_client.py send alice@example.com <conversation_id> \\
        "hey bob, this is encrypted end to end"

    python3 cipher_client.py read bob@example.com <conversation_id>

    python3 cipher_client.py list-conversations alice@example.com
"""

import argparse
import base64
import os
import sys
import time
from pathlib import Path
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

BASE_URL = os.environ.get("CIPHER_API_URL", "http://127.0.0.1:8000")
API_KEY = os.environ.get("CIPHER_API_KEY")
KEY_DIR = Path.home() / ".cipher_messaging"
HKDF_INFO = b"cipher-messaging-cek-wrap-v1"


class CipherClientError(Exception):
    """Raised for expected, user-facing problems (bad config, missing key,
    unknown recipient, etc). Callers such as the GUI can catch this
    specifically instead of crashing, unlike SystemExit which is meant
    only for a command-line process exiting."""


def configure(base_url: str | None = None, api_key: str | None = None) -> None:
    """Set the server URL / API key at runtime (used by the GUI's connect
    dialog). Falls back to CIPHER_API_URL / CIPHER_API_KEY env vars if
    never called."""
    global BASE_URL, API_KEY
    if base_url:
        BASE_URL = base_url.rstrip("/")
    if api_key:
        API_KEY = api_key


def _headers() -> dict:
    if not API_KEY:
        raise CipherClientError(
            "No server configured. Set CIPHER_API_KEY (and optionally "
            "CIPHER_API_URL) as environment variables, or call configure()."
        )
    return {"x-api-key": API_KEY, "Content-Type": "application/json"}


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

def _url(path: str) -> str:
    return f"{BASE_URL}{path}"


def api_get(path: str, params: dict | None = None) -> dict | list:
    resp = requests.get(_url(path), headers=_headers(), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def api_post(path: str, payload: dict) -> dict:
    resp = requests.post(_url(path), headers=_headers(), json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def api_put(path: str, payload: dict) -> dict:
    resp = requests.put(_url(path), headers=_headers(), json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------
# Local key storage
# --------------------------------------------------------------------------

def _key_path(email: str) -> Path:
    safe = email.replace("/", "_")
    return KEY_DIR / f"{safe}.private.pem"


def has_local_identity(email: str) -> bool:
    """Whether a local keypair already exists for this email — i.e. this
    looks like a returning user on this device rather than a first-time
    registration. Used by the GUI to greet returning users differently."""
    return _key_path(email).exists()


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def save_private_key(email: str, private_key: ec.EllipticCurvePrivateKey) -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = _key_path(email)
    path.write_bytes(pem)
    os.chmod(path, 0o600)


def load_private_key(email: str) -> ec.EllipticCurvePrivateKey:
    path = _key_path(email)
    if not path.exists():
        raise CipherClientError(
            f"No local private key for {email}. Register/create this identity first."
        )
    pem = path.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def public_key_b64(private_key: ec.EllipticCurvePrivateKey) -> str:
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode()


def load_public_key_from_b64(b64_der: str) -> ec.EllipticCurvePublicKey:
    der = base64.b64decode(b64_der)
    return serialization.load_der_public_key(der)


# --------------------------------------------------------------------------
# Crypto primitives
# --------------------------------------------------------------------------

def derive_shared_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    """ECDH + HKDF-SHA256 -> 32-byte AES key. Symmetric: A·B == B·A."""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[str, str]:
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()


def aes_gcm_decrypt(key: bytes, ciphertext_b64: str, iv_b64: str) -> bytes:
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    return AESGCM(key).decrypt(iv, ciphertext, None)


# --------------------------------------------------------------------------
# Identity directory
# --------------------------------------------------------------------------

def fetch_public_key(email: str) -> ec.EllipticCurvePublicKey:
    try:
        result = api_get(f"/identities/{quote(email, safe='')}")
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            raise CipherClientError(f"No published Identity for {email}. Have they registered?")
        raise
    return load_public_key_from_b64(result["public_key"])


def register(email: str) -> None:
    if _key_path(email).exists():
        print(f"{email} already has a local keypair at {_key_path(email)}")
        private_key = load_private_key(email)
    else:
        private_key = generate_keypair()
        save_private_key(email, private_key)
        print(f"Generated new keypair for {email}, stored at {_key_path(email)}")

    pub_b64 = public_key_b64(private_key)
    api_post("/identities", {"email": email, "public_key": pub_b64})  # server upserts
    print(f"Published public key for {email}")


# --------------------------------------------------------------------------
# Conversations
# --------------------------------------------------------------------------

def create_conversation(creator_email: str, participants: list[str], name: str | None) -> str:
    all_participants = sorted(set(participants + [creator_email]))
    payload = {
        "participants": all_participants,
        "creator_email": creator_email,
    }
    if name:
        payload["name"] = name
    result = api_post("/conversations", payload)
    print(f"Created conversation {result['id']} with {all_participants}")
    print(f"Invitations sent to: {', '.join([p for p in all_participants if p != creator_email])}")
    return result["id"]


def list_conversations_data(email: str) -> list[dict]:
    """Data-returning version for programmatic use (e.g. the GUI)."""
    return api_get("/conversations", params={"participant": email})


def list_conversations(email: str) -> None:
    """CLI wrapper: prints a human-readable list."""
    convos = list_conversations_data(email)
    if not convos:
        print("No conversations.")
        return
    for c in convos:
        preview = c.get("last_message_preview")
        note = "(has messages)" if preview else "(empty)"
        print(f"- {c['id']}  name={c.get('name') or '(unnamed)'}  {note}  participants={c['participants']}")


# --------------------------------------------------------------------------
# Invites
# --------------------------------------------------------------------------

def get_pending_invites(email: str) -> list[dict]:
    """Fetch all pending conversation invites for a user."""
    return api_get("/memberships/pending", params={"email": email})


def list_pending_invites(email: str) -> None:
    """CLI wrapper: prints pending invites."""
    invites = get_pending_invites(email)
    if not invites:
        print("No pending invites.")
        return
    for invite in invites:
        convo_id = invite["conversation_id"]
        membership_id = invite["id"]
        print(f"- Invite {membership_id} for conversation {convo_id}")


def respond_to_invite(membership_id: str, accept: bool) -> None:
    """Accept or decline a conversation invite."""
    status = "accepted" if accept else "declined"
    api_put(f"/memberships/{membership_id}", {"status": status})
    action = "accepted" if accept else "declined"
    print(f"Invite {action}: {membership_id}")


# --------------------------------------------------------------------------
# Sending
# --------------------------------------------------------------------------

def send_message(sender_email: str, conversation_id: str, text: str, disappearing_seconds: int | None = None) -> None:
    sender_private = load_private_key(sender_email)

    convo = api_get(f"/conversations/{conversation_id}")
    participants = convo["participants"]
    if sender_email not in participants:
        raise CipherClientError(f"{sender_email} is not a participant in {conversation_id}")

    # 1. Fresh random content key + encrypt the actual message with it.
    cek = os.urandom(32)
    encrypted_content, iv = aes_gcm_encrypt(cek, text.encode("utf-8"))

    # 2. Seal the CEK for every participant (including the sender, so
    #    they can read their own sent messages back later).
    sealed_cek = []
    for recipient_email in participants:
        recipient_pub = fetch_public_key(recipient_email)
        wrap_key = derive_shared_key(sender_private, recipient_pub)
        c, i = aes_gcm_encrypt(wrap_key, cek)
        sealed_cek.append({"recipient": recipient_email, "c": c, "i": i})

    payload = {
        "conversation_id": conversation_id,
        "participants": participants,
        "encrypted_content": encrypted_content,
        "iv": iv,
        "sealed_cek": sealed_cek,
        "sender_email": sender_email,  # needed by recipients to pick the right public key
    }
    if disappearing_seconds:
        payload["expires_at"] = _iso_in(disappearing_seconds)

    msg = api_post("/messages", payload)

    # Update conversation preview (also encrypted, per-recipient sealed).
    preview_cek = os.urandom(32)
    preview_text = text if len(text) <= 80 else text[:77] + "..."
    preview_ct, preview_iv = aes_gcm_encrypt(preview_cek, preview_text.encode("utf-8"))
    preview_sealed = []
    for recipient_email in participants:
        recipient_pub = fetch_public_key(recipient_email)
        wrap_key = derive_shared_key(sender_private, recipient_pub)
        c, i = aes_gcm_encrypt(wrap_key, preview_cek)
        preview_sealed.append({"recipient": recipient_email, "c": c, "i": i})

    api_put(
        f"/conversations/{conversation_id}",
        {
            "last_message_at": _iso_now(),
            "last_message_preview": preview_ct,
            "last_message_preview_iv": preview_iv,
            "last_message_sealed_cek": preview_sealed,
            "last_message_sender": sender_email,
        },
    )

    print(f"Sent message {msg['id']} in {conversation_id}")


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _iso_in(seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


# --------------------------------------------------------------------------
# Reading / decrypting
# --------------------------------------------------------------------------

def read_conversation_data(reader_email: str, conversation_id: str) -> list[dict]:
    """Data-returning version: decrypts every message and returns a list
    of {id, sender_email, created_date, plaintext} dicts (plaintext is
    None with an `error` key set if decryption/addressing failed), for
    programmatic use (e.g. the GUI)."""
    reader_private = load_private_key(reader_email)
    messages = api_get("/messages", params={"conversation_id": conversation_id})

    pubkey_cache: dict[str, ec.EllipticCurvePublicKey] = {}
    results = []

    for m in messages:
        sender_email = m.get("sender_email", "unknown")
        entry = {"id": m["id"], "sender_email": sender_email, "created_date": m.get("created_date", "")}

        sealed_entry = next((s for s in m["sealed_cek"] if s["recipient"] == reader_email), None)
        if sealed_entry is None:
            entry["plaintext"] = None
            entry["error"] = f"not addressed to {reader_email}"
            results.append(entry)
            continue

        try:
            if sender_email not in pubkey_cache:
                pubkey_cache[sender_email] = fetch_public_key(sender_email)
            wrap_key = derive_shared_key(reader_private, pubkey_cache[sender_email])
            cek = aes_gcm_decrypt(wrap_key, sealed_entry["c"], sealed_entry["i"])
            entry["plaintext"] = aes_gcm_decrypt(cek, m["encrypted_content"], m["iv"]).decode("utf-8")
        except Exception as e:  # noqa: BLE001 - surface decrypt failures plainly
            entry["plaintext"] = None
            entry["error"] = f"decryption failed: {e}"

        results.append(entry)

    return results


def read_conversation(reader_email: str, conversation_id: str) -> None:
    """CLI wrapper: prints a human-readable transcript."""
    entries = read_conversation_data(reader_email, conversation_id)
    if not entries:
        print("No messages.")
        return
    for e in entries:
        if e.get("error"):
            print(f"[{e['id']}] {e['sender_email']}: <{e['error']}>")
        else:
            print(f"[{e['created_date']}] {e['sender_email']}: {e['plaintext']}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end encrypted client for Cipher Messaging.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("register", help="Generate (or reuse) a local keypair and publish the public key.")
    p.add_argument("email")

    p = sub.add_parser("create-conversation", help="Start a new conversation.")
    p.add_argument("email", help="Your email (must be registered)")
    p.add_argument("--with", dest="with_", nargs="+", required=True, help="Other participant email(s)")
    p.add_argument("--name", default=None)

    p = sub.add_parser("list-conversations", help="List conversations you're part of.")
    p.add_argument("email")

    p = sub.add_parser("send", help="Send an encrypted message.")
    p.add_argument("email", help="Your email (must be registered)")
    p.add_argument("conversation_id")
    p.add_argument("text")
    p.add_argument("--disappear-after", type=int, default=None, metavar="SECONDS")

    p = sub.add_parser("read", help="Fetch and decrypt all messages in a conversation.")
    p.add_argument("email")
    p.add_argument("conversation_id")

    p = sub.add_parser("list-invites", help="List pending conversation invites.")
    p.add_argument("email", help="Your email")

    p = sub.add_parser("accept-invite", help="Accept a conversation invite.")
    p.add_argument("membership_id", help="The invite membership ID")

    p = sub.add_parser("decline-invite", help="Decline a conversation invite.")
    p.add_argument("membership_id", help="The invite membership ID")

    args = parser.parse_args()

    try:
        if args.command == "register":
            register(args.email)
        elif args.command == "create-conversation":
            create_conversation(args.email, args.with_, args.name)
        elif args.command == "list-conversations":
            list_conversations(args.email)
        elif args.command == "send":
            send_message(args.email, args.conversation_id, args.text, args.disappear_after)
        elif args.command == "read":
            read_conversation(args.email, args.conversation_id)
        elif args.command == "list-invites":
            list_pending_invites(args.email)
        elif args.command == "accept-invite":
            respond_to_invite(args.membership_id, accept=True)
        elif args.command == "decline-invite":
            respond_to_invite(args.membership_id, accept=False)
    except (requests.exceptions.ConnectionError, requests.HTTPError, CipherClientError) as e:
        if isinstance(e, requests.HTTPError):
            body = e.response.text if e.response is not None else ""
            raise SystemExit(f"API error: {e}\n{body}")
        raise SystemExit(str(e))


if __name__ == "__main__":
    main()


# --------------------------------------------------------------------------
# Limitations (read before relying on this for anything sensitive)
# --------------------------------------------------------------------------
# * The server's x-api-key is a single shared secret gating the whole
#   deployment — it does not authenticate individual users against each
#   other. Anyone holding that key could publish a fake public key under
#   someone else's email (a MITM/impersonation risk). A real system needs
#   per-user auth (e.g. JWTs) plus key-verification (safety numbers, a
#   trusted directory, etc.).
# * Private keys sit unencrypted on disk under ~/.cipher_messaging. Add a
#   passphrase-derived wrapping key if this leaves a trusted machine.
# * No forward secrecy — static ECDH keys mean a compromised private key
#   can decrypt past sealed_cek entries. A production system would rotate
#   keys (e.g. Double Ratchet, as in Signal).
# * `sender_email` is sent in the clear so recipients know which public
#   key to use; it is not itself encrypted or authenticated beyond the
#   AES-GCM tag on the message it accompanies.
# * If you deploy on Render's free tier with the default SQLite database,
#   your data is wiped on every redeploy/restart — see server/README.md.
