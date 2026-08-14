"""
Cipher Messaging API — a small, self-hostable backend for end-to-end
encrypted messaging.

The server is deliberately "dumb": it stores and relays ciphertext and
never sees plaintext, private keys, or content encryption keys. All
crypto happens on the client (see cipher_client.py).

Entities
--------
Identity      — email -> public key directory
Conversation  — a set of participant emails (+ encrypted preview of the
                 last message, for inbox-style UIs)
Message       — one encrypted message, with a per-recipient sealed
                 content key (sealed_cek)

Auth: every request must send a header `x-api-key` matching the
API_KEY environment variable. Set this on Render (or generate one with
`openssl rand -hex 32`) — do NOT hardcode a real key into this file.

Storage: SQLAlchemy against DATABASE_URL (defaults to a local SQLite
file). Render's free web services have an EPHEMERAL filesystem — data
in a local sqlite file will be wiped on every redeploy/restart. Point
DATABASE_URL at a Supabase Postgres project instead to persist data —
see README.md for the connection string to use.

Run locally:
    pip install -r requirements.txt
    API_KEY=dev-secret uvicorn main:app --reload
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from sqlalchemy import JSON, Column, DateTime, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

API_KEY = os.environ.get("API_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./data.db")

if not API_KEY:
    # Fail loudly rather than silently running with no auth.
    raise RuntimeError(
        "API_KEY environment variable is not set. Set it before starting "
        "the server (locally: `export API_KEY=$(openssl rand -hex 32)`; "
        "on Render: set it in the service's Environment tab)."
    )

# Some providers hand out `postgres://` (old Heroku-style); SQLAlchemy 1.4+
# requires the `postgresql://` scheme. Supabase already gives you the
# correct form, but normalize just in case a connection string gets
# copied from somewhere else.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    # Hosted Postgres (Supabase included) can silently drop idle
    # connections; pool_pre_ping tests each connection before use so a
    # stale one gets transparently replaced instead of raising mid-request.
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------
# DB models
# --------------------------------------------------------------------------

class IdentityRow(Base):
    __tablename__ = "identities"
    id = Column(String, primary_key=True, default=new_id)
    email = Column(String, unique=True, index=True, nullable=False)
    public_key = Column(String, nullable=False)
    created_date = Column(String, default=now_iso)
    updated_date = Column(String, default=now_iso)


class ConversationRow(Base):
    __tablename__ = "conversations"
    id = Column(String, primary_key=True, default=new_id)
    name = Column(String, nullable=True)
    participants = Column(JSON, nullable=False)  # list[str]
    last_message_at = Column(String, nullable=True)
    last_message_preview = Column(String, nullable=True)
    last_message_preview_iv = Column(String, nullable=True)
    last_message_sealed_cek = Column(JSON, nullable=True)  # list[dict]
    last_message_sender = Column(String, nullable=True)
    disappearing_ms = Column(String, default="0")
    created_date = Column(String, default=now_iso)
    updated_date = Column(String, default=now_iso)


class MessageRow(Base):
    __tablename__ = "messages"
    id = Column(String, primary_key=True, default=new_id)
    conversation_id = Column(String, index=True, nullable=False)
    participants = Column(JSON, nullable=False)  # list[str]
    encrypted_content = Column(String, nullable=False)
    iv = Column(String, nullable=False)
    sealed_cek = Column(JSON, nullable=False)  # list[dict]
    sender_email = Column(String, nullable=False)
    expires_at = Column(String, nullable=True)
    created_date = Column(String, default=now_iso)
    updated_date = Column(String, default=now_iso)


Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------

def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="missing or invalid x-api-key header")


# --------------------------------------------------------------------------
# Pydantic schemas (request/response bodies)
# --------------------------------------------------------------------------

class SealedCek(BaseModel):
    recipient: str
    c: str
    i: str


class IdentityIn(BaseModel):
    email: str
    public_key: str


class IdentityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    public_key: str
    created_date: str
    updated_date: str


class ConversationIn(BaseModel):
    participants: list[str]
    name: Optional[str] = None
    disappearing_ms: Optional[int] = 0


class ConversationUpdate(BaseModel):
    name: Optional[str] = None
    last_message_at: Optional[str] = None
    last_message_preview: Optional[str] = None
    last_message_preview_iv: Optional[str] = None
    last_message_sealed_cek: Optional[list[SealedCek]] = None
    last_message_sender: Optional[str] = None
    disappearing_ms: Optional[int] = None


class ConversationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: Optional[str]
    participants: list[str]
    last_message_at: Optional[str]
    last_message_preview: Optional[str]
    last_message_preview_iv: Optional[str]
    last_message_sealed_cek: Optional[list[dict]]
    last_message_sender: Optional[str]
    disappearing_ms: Optional[str]
    created_date: str
    updated_date: str


class MessageIn(BaseModel):
    conversation_id: str
    participants: list[str]
    encrypted_content: str
    iv: str
    sealed_cek: list[SealedCek]
    sender_email: str
    expires_at: Optional[str] = None


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    conversation_id: str
    participants: list[str]
    encrypted_content: str
    iv: str
    sealed_cek: list[dict]
    sender_email: str
    expires_at: Optional[str]
    created_date: str
    updated_date: str


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------

app = FastAPI(title="Cipher Messaging API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health():
    """Health check — also what Render pings to confirm the service is up."""
    return {"status": "ok", "time": now_iso()}


# ---- Identities ----------------------------------------------------------

@app.post("/identities", response_model=IdentityOut, dependencies=[Depends(require_api_key)])
def upsert_identity(body: IdentityIn, db: Session = Depends(get_db)):
    row = db.query(IdentityRow).filter(IdentityRow.email == body.email).first()
    if row:
        row.public_key = body.public_key
        row.updated_date = now_iso()
    else:
        row = IdentityRow(id=new_id(), email=body.email, public_key=body.public_key)
        db.add(row)
    db.commit()
    db.refresh(row)
    return row


@app.get("/identities/{email}", response_model=IdentityOut, dependencies=[Depends(require_api_key)])
def get_identity(email: str, db: Session = Depends(get_db)):
    row = db.query(IdentityRow).filter(IdentityRow.email == email).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"no identity for {email}")
    return row


# ---- Conversations ---------------------------------------------------------

@app.post("/conversations", response_model=ConversationOut, dependencies=[Depends(require_api_key)])
def create_conversation(body: ConversationIn, db: Session = Depends(get_db)):
    row = ConversationRow(
        id=new_id(),
        name=body.name,
        participants=sorted(set(body.participants)),
        disappearing_ms=str(body.disappearing_ms or 0),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@app.get("/conversations", response_model=list[ConversationOut], dependencies=[Depends(require_api_key)])
def list_conversations(participant: str = Query(...), db: Session = Depends(get_db)):
    rows = db.query(ConversationRow).order_by(ConversationRow.updated_date.desc()).all()
    return [r for r in rows if participant in (r.participants or [])]


@app.get("/conversations/{conversation_id}", response_model=ConversationOut, dependencies=[Depends(require_api_key)])
def get_conversation(conversation_id: str, db: Session = Depends(get_db)):
    row = db.query(ConversationRow).filter(ConversationRow.id == conversation_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="conversation not found")
    return row


@app.put("/conversations/{conversation_id}", response_model=ConversationOut, dependencies=[Depends(require_api_key)])
def update_conversation(conversation_id: str, body: ConversationUpdate, db: Session = Depends(get_db)):
    row = db.query(ConversationRow).filter(ConversationRow.id == conversation_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="conversation not found")
    data = body.model_dump(exclude_unset=True)
    for field, value in data.items():
        if field == "last_message_sealed_cek" and value is not None:
            value = [v if isinstance(v, dict) else v.model_dump() for v in value]
        if field == "disappearing_ms" and value is not None:
            value = str(value)
        setattr(row, field, value)
    row.updated_date = now_iso()
    db.commit()
    db.refresh(row)
    return row


# ---- Messages --------------------------------------------------------------

@app.post("/messages", response_model=MessageOut, dependencies=[Depends(require_api_key)])
def create_message(body: MessageIn, db: Session = Depends(get_db)):
    convo = db.query(ConversationRow).filter(ConversationRow.id == body.conversation_id).first()
    if not convo:
        raise HTTPException(status_code=404, detail="conversation not found")
    if body.sender_email not in (convo.participants or []):
        raise HTTPException(status_code=403, detail="sender is not a participant in this conversation")

    row = MessageRow(
        id=new_id(),
        conversation_id=body.conversation_id,
        participants=body.participants,
        encrypted_content=body.encrypted_content,
        iv=body.iv,
        sealed_cek=[s.model_dump() for s in body.sealed_cek],
        sender_email=body.sender_email,
        expires_at=body.expires_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@app.get("/messages", response_model=list[MessageOut], dependencies=[Depends(require_api_key)])
def list_messages(conversation_id: str = Query(...), db: Session = Depends(get_db)):
    rows = (
        db.query(MessageRow)
        .filter(MessageRow.conversation_id == conversation_id)
        .order_by(MessageRow.created_date.asc())
        .all()
    )

    live, expired_ids = [], []
    now = now_iso()
    for r in rows:
        if r.expires_at and r.expires_at <= now:
            expired_ids.append(r.id)
        else:
            live.append(r)

    if expired_ids:
        db.query(MessageRow).filter(MessageRow.id.in_(expired_ids)).delete(synchronize_session=False)
        db.commit()

    return live
