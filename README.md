# Cipher Messaging API

A small, self-hostable backend for end-to-end encrypted messaging. It
stores and relays ciphertext only — the server never sees plaintext,
private keys, or content encryption keys. All crypto happens in the
client (`cipher_client.py` / `gui_client.py`).

Real user accounts are handled by **Supabase Auth** — no shared API
key baked into the app. Each user signs up with an email + password;
the server verifies their session token on every request.

## 1. Set up Supabase (auth + database)

1. Create a free account at [supabase.com](https://supabase.com) and a
   new project. Set a database password when prompted — save it, you'll
   need it for the DB connection string.
2. **Auth is on by default** — email/password sign-up works out of the
   box. Optional but recommended for quick testing: **Authentication →
   Providers → Email** and turn **off** "Confirm email", so new accounts
   can log in immediately instead of needing to click a confirmation
   link first. (Leave it on for anything beyond personal testing.)
3. You'll need three values out of this project, used in two very
   different places:

   | Value | Where to find it | Goes where | Secret? |
   |---|---|---|---|
   | Project URL | Settings → API → Project URL | baked into the **client app** | No — public by design |
   | `anon` / `public` key | Settings → API → Project API keys | baked into the **client app** | No — public by design |
   | JWT Secret | Settings → API → JWT Settings → JWT Secret | set on **this server** (Render env var) | **Yes** — never ship this |

   Supabase's anon key is intentionally safe to embed in a distributed
   app — it identifies the *project*, not a *user*; real access control
   happens via the JWT Secret check this server performs. The JWT
   Secret is what actually verifies a token wasn't forged, so it must
   stay server-side only.

## 2. Deploy the server to Render (free tier)

1. Push this `server/` folder to a GitHub repo.
2. In Render: **New → Blueprint**, point it at your repo. It reads
   `render.yaml` and creates the service, prompting you to fill in the
   env vars it can't generate itself:
   - `SUPABASE_JWT_SECRET` — from the table above
   - `DATABASE_URL` — see step 3 below
   - Doing it by hand instead (**New → Web Service**)? Set:
     - **Root Directory:** `server`
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. **Database connection string:** Supabase project → **Settings →
   Database → Connection string** → choose the **Transaction pooler**
   string (port `6543`, not the direct `5432` one — the free tier's
   direct-connection limit gets exhausted fast under Render's usage
   pattern). Replace `[YOUR-PASSWORD]` with your actual DB password:
   ```
   postgresql://postgres.xxxxxxxxxxxx:[YOUR-PASSWORD]@aws-0-us-east-1.pooler.supabase.com:6543/postgres
   ```
   Set that as `DATABASE_URL`.
4. Once deployed, visit `https://<your-service-name>.onrender.com` —
   you should see `{"status": "ok", ...}`.

Render's free web services spin down after 15 minutes of inactivity and
take ~30–60s to wake back up on the next request — fine for personal
use, just expect an occasional cold-start delay.

**Python version:** this repo pins Python to 3.11 (via `runtime.txt`
and `render.yaml`'s `PYTHON_VERSION`). Don't remove that — newer Python
versions don't yet have prebuilt wheels for some dependencies (e.g.
`pydantic-core`), so Render tries to compile them from source and fails
(its build environment can't write to the Rust build cache).

You can confirm data is landing correctly from Supabase's **Table
Editor**: `identities`, `conversations`, and `messages` tables appear
after you sign up a user or send a message. Signed-up users themselves
show up under **Authentication → Users**.

## 3. Configure the client app

In `gui_client.py`, fill in the `DEFAULT_*` constants near the top with
the Project URL + anon key from step 1, plus your Render URL from step
2. These three are safe to bake in and ship — see the comment above
them for why. Nothing else needs configuring; end users just sign up
or log in with email + password.

## Run the server locally

```bash
pip install -r requirements.txt
export SUPABASE_JWT_SECRET=...   # from your Supabase project
uvicorn main:app --reload
```

## How invitations work

When a user starts a conversation, every other participant is added
with `pending` status. They'll see it as an invitation in the app and
must accept before they can send or read anything in it — enforced
server-side (`POST /messages` and `GET /messages` both check the
caller's status is `accepted`), not just hidden in the UI. Declining
sets their status to `declined`, after which they lose access. The
creator is always auto-accepted.

## Security notes

- **Auth:** every request (besides the health check) needs
  `Authorization: Bearer <token>`, where the token comes from Supabase
  Auth and is verified here against `SUPABASE_JWT_SECRET`. A user can
  only publish an `Identity` for their own authenticated email, and can
  only send messages as themselves — no more shared-key impersonation
  risk.
- **No forward secrecy:** each user's messaging keypair is static, not
  rotated per-session. See the client's docstring for more on this
  trade-off.
- This is a reference implementation for learning/prototyping, not an
  audited security product.
