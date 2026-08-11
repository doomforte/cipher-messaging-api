# Cipher Messaging API

A small, self-hostable backend for end-to-end encrypted messaging. It
stores and relays ciphertext only — the server never sees plaintext,
private keys, or content encryption keys. All crypto happens in the
client (`cipher_client.py`).

## Deploy to Render (free tier)

1. Push this `server/` folder to a GitHub repo (Render deploys from git).
2. In the Render dashboard: **New → Blueprint**, point it at your repo.
   Render will read `render.yaml` and set everything up automatically —
   including generating a random `API_KEY` for you.
   - No `render.yaml`/Blueprint support, or prefer doing it by hand?
     Use **New → Web Service** instead, pick the repo, and set:
     - **Root Directory:** `server`
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
     - **Environment Variable:** `API_KEY` = (generate one with
       `openssl rand -hex 32` and paste it in)
3. Once deployed, your API lives at `https://<your-service-name>.onrender.com`.
   Visit that URL — you should see `{"status": "ok", ...}`.

Render's free web services spin down after 15 minutes of inactivity and
take ~30–60s to wake back up on the next request — fine for personal use,
just expect a cold-start delay occasionally.

## ⚠️ Persistence

Render's **free** web services have an *ephemeral* filesystem: the
default `sqlite:///./data.db` gets wiped every time the service restarts
or redeploys. That's fine for trying things out, but not for real use.

To persist data across restarts, point `DATABASE_URL` at a free hosted
Postgres instance instead — e.g. [Neon](https://neon.tech) or
[Supabase](https://supabase.com) both have free tiers. Once you have a
connection string, set it as the `DATABASE_URL` env var on Render:

```
DATABASE_URL=postgresql://user:password@host/dbname
```

The server auto-detects Postgres vs SQLite from the URL — no code
changes needed.

## Run locally

```bash
pip install -r requirements.txt
export API_KEY=dev-secret
uvicorn main:app --reload
```

## Security notes

- **Auth:** every request needs a `x-api-key` header matching `API_KEY`.
  This gates who can read/write your server at all — it does not
  authenticate individual *users* against each other. Anyone with the
  API key could publish an `Identity` under someone else's email
  (impersonation risk). For real multi-user auth you'd want per-user
  tokens (e.g. JWT) instead of one shared key.
- **No forward secrecy:** keys are static ECDH keypairs, not rotated
  per-session. See the client's docstring for more on this trade-off.
- This is a reference implementation for learning/prototyping, not an
  audited security product.
