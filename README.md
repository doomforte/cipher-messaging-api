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

**Python version:** this repo pins Python to 3.11 (via `runtime.txt` and
`render.yaml`'s `PYTHON_VERSION`). Don't remove that — newer Python
versions (3.13+) don't yet have prebuilt wheels for some dependencies
(e.g. `pydantic-core`), which makes Render try to compile them from
source and fail, since its build environment can't write to the Rust
build cache.

## ⚠️ Persistence — set up Supabase

Render's **free** web services have an *ephemeral* filesystem: the
default `sqlite:///./data.db` gets wiped every time the service restarts
or redeploys. To actually keep your data, point `DATABASE_URL` at a
[Supabase](https://supabase.com) Postgres project (free tier, no card
required for the first project):

1. Create a Supabase account and a new project. Pick any name/region;
   set a database password when prompted (save it — you'll need it in
   the connection string).
2. In the project dashboard: **Settings → Database → Connection string**.
   Choose the **Transaction pooler** connection string (port `6543`), not
   the direct connection (port `5432`). The pooler is designed for
   environments like Render that open lots of short-lived connections;
   the direct connection has a low connection-count limit on the free
   tier and will get exhausted quickly.
3. Copy that URI and replace `[YOUR-PASSWORD]` with your actual database
   password. It'll look like:
   ```
   postgresql://postgres.xxxxxxxxxxxx:[YOUR-PASSWORD]@aws-0-us-east-1.pooler.supabase.com:6543/postgres
   ```
4. In Render: your service → **Environment** tab → set `DATABASE_URL` to
   that string → save (Render will redeploy automatically).
5. Check the Logs tab for a clean startup with no database errors. The
   server creates its tables automatically on first boot
   (`Base.metadata.create_all`) — no migration step needed for this
   project's scope.

No code changes needed — the server auto-detects Postgres vs SQLite from
the URL. You can confirm data is landing in Supabase from **Table
Editor** in the Supabase dashboard: you should see `identities`,
`conversations`, and `messages` tables appear after you register a user
or send a message.

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
