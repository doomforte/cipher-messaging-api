#!/usr/bin/env python3
"""
gui_client.py — Desktop GUI for Cipher Messaging, built on top of
cipher_client.py (same encryption, same server API — this just adds a
window instead of a command line).

Run:
    python3 gui_client.py

On first launch it asks for your server URL + API key (or reads them
from CIPHER_API_URL / CIPHER_API_KEY env vars if set), then lets you
register a new identity or continue as a returning one. Network calls
run on a background thread so the window never freezes; all
encryption/decryption happens locally, same as the CLI.
"""

import queue
import re
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

import requests

import cipher_client as cc

REFRESH_MS = 5000  # how often to poll for new conversations/messages
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------------------------------------------------------------------
# Palette / type scale — kept in one place so the look stays consistent.
# ---------------------------------------------------------------------------

C_SIDEBAR = "#1a1f2e"
C_SIDEBAR_ROW_HOVER = "#242b3d"
C_SIDEBAR_ROW_SELECTED = "#2f3750"
C_SIDEBAR_TEXT = "#e5e7eb"
C_SIDEBAR_SUBTEXT = "#8b93a7"
C_SIDEBAR_BORDER = "#2a3142"

C_MAIN_BG = "#f4f5f7"
C_HEADER_BG = "#ffffff"
C_HEADER_BORDER = "#e5e7eb"
C_TEXT_DARK = "#1e2330"
C_TEXT_MUTED = "#6b7280"

C_ACCENT = "#5b5fef"
C_ACCENT_HOVER = "#4a4ed9"
C_ACCENT_TEXT = "#ffffff"

C_BUBBLE_ME_BG = "#5b5fef"
C_BUBBLE_ME_TEXT = "#ffffff"
C_BUBBLE_OTHER_BG = "#ffffff"
C_BUBBLE_OTHER_BORDER = "#e5e7eb"
C_BUBBLE_OTHER_TEXT = "#1e2330"

C_ERROR = "#dc2626"
C_SUCCESS = "#16a34a"

F_FAMILY = "Segoe UI"  # Tk falls back gracefully if unavailable on this OS


def font(size, weight="normal"):
    return (F_FAMILY, size, weight)


# ---------------------------------------------------------------------------
# Small reusable widgets
# ---------------------------------------------------------------------------

class ScrollableFrame(ttk.Frame):
    """A vertically-scrollable container. Put widgets in `.inner`."""

    def __init__(self, parent, bg):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, bg=bg, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self._inner_id, width=e.width))
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.canvas.bind("<Enter>", lambda e: self._bind_wheel())
        self.canvas.bind("<Leave>", lambda e: self._unbind_wheel())

    def _bind_wheel(self):
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)
        self.canvas.bind_all("<Button-4>", self._on_wheel)
        self.canvas.bind_all("<Button-5>", self._on_wheel)

    def _unbind_wheel(self):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_wheel(self, event):
        delta = -1 if getattr(event, "num", None) == 4 else (1 if getattr(event, "num", None) == 5 else None)
        if delta is None:
            delta = -1 if event.delta > 0 else 1
        self.canvas.yview_scroll(delta, "units")

    def clear(self):
        for w in self.inner.winfo_children():
            w.destroy()

    def scroll_to_bottom(self):
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)


def bind_recursive(widget, event, handler):
    """Bind an event to a widget and every descendant, so clicking anywhere
    on a composite row (frame + labels) triggers the same handler."""
    widget.bind(event, handler)
    for child in widget.winfo_children():
        bind_recursive(child, event, handler)


class RoundedButton(tk.Label):
    """A flat, colored button (ttk buttons can't easily get custom
    colors on every platform, so a styled Label with click/hover
    bindings gives a more consistent, modern look)."""

    def __init__(self, parent, text, command, bg=C_ACCENT, hover_bg=C_ACCENT_HOVER, fg=C_ACCENT_TEXT, pad=(16, 8), **kwargs):
        super().__init__(
            parent, text=text, bg=bg, fg=fg, font=font(10, "bold"),
            padx=pad[0], pady=pad[1], cursor="hand2", **kwargs,
        )
        self._bg, self._hover_bg, self._command = bg, hover_bg, command
        self.bind("<Button-1>", lambda e: self._command())
        self.bind("<Enter>", lambda e: self.config(bg=self._hover_bg))
        self.bind("<Leave>", lambda e: self.config(bg=self._bg))

    def set_enabled(self, enabled: bool):
        if enabled:
            self.config(state="normal", cursor="hand2")
            self.bind("<Button-1>", lambda e: self._command())
        else:
            self.unbind("<Button-1>")
            self.config(cursor="arrow")


class PlaceholderEntry(tk.Entry):
    """A tk.Entry with placeholder text, since ttk.Entry can't easily
    theme background/border to match the rest of the app."""

    def __init__(self, parent, placeholder="", show=None, **kwargs):
        super().__init__(
            parent, font=font(11), bg="#ffffff", fg=C_TEXT_DARK,
            relief="flat", highlightthickness=1,
            highlightbackground="#d1d5db", highlightcolor=C_ACCENT,
            insertbackground=C_TEXT_DARK, show=show, **kwargs,
        )
        self._placeholder = placeholder
        self._placeholder_active = False
        self._real_show = show
        if placeholder:
            self._show_placeholder()
            self.bind("<FocusIn>", self._on_focus_in)
            self.bind("<FocusOut>", self._on_focus_out)

    def _show_placeholder(self):
        self.insert(0, self._placeholder)
        self.config(fg="#9ca3af")
        if self._real_show:
            self.config(show="")
        self._placeholder_active = True

    def _on_focus_in(self, _e):
        if self._placeholder_active:
            self.delete(0, tk.END)
            self.config(fg=C_TEXT_DARK)
            if self._real_show:
                self.config(show=self._real_show)
            self._placeholder_active = False

    def _on_focus_out(self, _e):
        if not self.get():
            self._show_placeholder()

    def value(self) -> str:
        return "" if self._placeholder_active else self.get().strip()


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class CipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher Messaging")
        self.geometry("980x640")
        self.minsize(720, 480)
        self.configure(bg=C_MAIN_BG)

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Vertical.TScrollbar", background=C_MAIN_BG, troughcolor=C_MAIN_BG, borderwidth=0)

        self.email: str | None = None
        self.conversations: list[dict] = []
        self.selected_conversation_id: str | None = None
        self._refresh_job = None
        self._task_queue: queue.Queue = queue.Queue()
        self.after(80, self._poll_task_queue)

        self._build_connect_screen()

    # ----------------------------------------------------------------
    # Background work helper — Tkinter isn't thread-safe, so worker
    # threads only compute; all widget updates happen back on the main
    # thread via this queue, drained on a timer.
    # ----------------------------------------------------------------

    def run_async(self, work, on_success=None, on_error=None):
        def worker():
            try:
                result = work()
                self._task_queue.put((result, on_success))
            except Exception as e:  # noqa: BLE001 - surfaced to the user, not swallowed
                self._task_queue.put((e, on_error))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_task_queue(self):
        try:
            while True:
                payload, callback = self._task_queue.get_nowait()
                if callback:
                    callback(payload)
        except queue.Empty:
            pass
        self.after(80, self._poll_task_queue)

    def _clear(self):
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None
        for w in self.winfo_children():
            w.destroy()

    # ----------------------------------------------------------------
    # Screen 1: connect to server
    # ----------------------------------------------------------------

    def _build_connect_screen(self):
        self._clear()
        self.configure(bg=C_MAIN_BG)

        card = tk.Frame(self, bg="#ffffff", padx=48, pady=40, highlightbackground="#e5e7eb", highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(card, text="Cipher Messaging", font=font(20, "bold"), bg="#ffffff", fg=C_TEXT_DARK).pack(anchor="w")
        tk.Label(card, text="Connect to your server to get started.", font=font(10), bg="#ffffff", fg=C_TEXT_MUTED).pack(
            anchor="w", pady=(2, 24)
        )

        tk.Label(card, text="SERVER URL", font=font(8, "bold"), bg="#ffffff", fg=C_TEXT_MUTED).pack(anchor="w")
        url_entry = PlaceholderEntry(card, placeholder="https://your-service.onrender.com", width=42)
        if cc.BASE_URL and cc.BASE_URL != "http://127.0.0.1:8000":
            url_entry.delete(0, tk.END)
            url_entry.insert(0, cc.BASE_URL)
            url_entry.config(fg=C_TEXT_DARK)
            url_entry._placeholder_active = False
        url_entry.pack(anchor="w", ipady=6, pady=(4, 16), fill="x")

        tk.Label(card, text="API KEY", font=font(8, "bold"), bg="#ffffff", fg=C_TEXT_MUTED).pack(anchor="w")
        key_entry = PlaceholderEntry(card, placeholder="the API_KEY you set on the server", show="*", width=42)
        if cc.API_KEY:
            key_entry.delete(0, tk.END)
            key_entry.insert(0, cc.API_KEY)
            key_entry.config(fg=C_TEXT_DARK, show="*")
            key_entry._placeholder_active = False
        key_entry.pack(anchor="w", ipady=6, pady=(4, 8), fill="x")

        status_label = tk.Label(card, text="", font=font(9), bg="#ffffff", fg=C_ERROR, wraplength=340, justify="left")
        status_label.pack(anchor="w", pady=(4, 16))

        def do_connect():
            url, key = url_entry.value(), key_entry.value()
            if not url or not key:
                status_label.config(text="Both fields are required.", fg=C_ERROR)
                return
            cc.configure(base_url=url, api_key=key)
            status_label.config(text="Connecting…", fg=C_TEXT_MUTED)
            connect_btn.set_enabled(False)

            def check():
                requests.get(f"{cc.BASE_URL}/", timeout=10).raise_for_status()

            def on_ok(_):
                self._build_login_screen()

            def on_err(err):
                connect_btn.set_enabled(True)
                status_label.config(text=f"Couldn't reach server: {err}", fg=C_ERROR)

            self.run_async(check, on_ok, on_err)

        connect_btn = RoundedButton(card, "Connect", do_connect)
        connect_btn.pack(anchor="w")
        self.bind("<Return>", lambda e: do_connect())

    # ----------------------------------------------------------------
    # Screen 2: register / continue with an identity
    # ----------------------------------------------------------------

    def _build_login_screen(self):
        self._clear()
        self.unbind("<Return>")
        self.configure(bg=C_MAIN_BG)

        card = tk.Frame(self, bg="#ffffff", padx=48, pady=40, highlightbackground="#e5e7eb", highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(card, text="Welcome", font=font(20, "bold"), bg="#ffffff", fg=C_TEXT_DARK).pack(anchor="w")
        subtitle = tk.Label(
            card,
            text="Enter your email. New here? We'll create a secure identity\nfor you automatically — no password needed.",
            font=font(10), bg="#ffffff", fg=C_TEXT_MUTED, justify="left",
        )
        subtitle.pack(anchor="w", pady=(2, 20))

        tk.Label(card, text="EMAIL", font=font(8, "bold"), bg="#ffffff", fg=C_TEXT_MUTED).pack(anchor="w")
        email_entry = PlaceholderEntry(card, placeholder="you@example.com", width=42)
        email_entry.pack(anchor="w", ipady=6, pady=(4, 8), fill="x")

        hint_label = tk.Label(card, text=" ", font=font(9), bg="#ffffff", fg=C_TEXT_MUTED)
        hint_label.pack(anchor="w", pady=(0, 4))

        status_label = tk.Label(card, text="", font=font(9), bg="#ffffff", fg=C_ERROR, wraplength=340, justify="left")
        status_label.pack(anchor="w", pady=(4, 16))

        def update_hint(_e=None):
            value = email_entry.value()
            if not value:
                hint_label.config(text=" ")
                action_btn.config(text="Continue")
            elif not EMAIL_RE.match(value):
                hint_label.config(text="Enter a valid email address.", fg=C_ERROR)
                action_btn.config(text="Continue")
            elif cc.has_local_identity(value):
                hint_label.config(text="Welcome back — we found your existing identity on this device.", fg=C_SUCCESS)
                action_btn.config(text="Log In")
            else:
                hint_label.config(text="New identity — a secure keypair will be generated for you.", fg=C_TEXT_MUTED)
                action_btn.config(text="Create Account")

        email_entry.bind("<KeyRelease>", update_hint)

        def do_continue():
            email = email_entry.value()
            if not email or not EMAIL_RE.match(email):
                status_label.config(text="Enter a valid email address.")
                return
            status_label.config(text="Setting up your identity…", fg=C_TEXT_MUTED)
            action_btn.set_enabled(False)

            def work():
                cc.register(email)  # creates a local keypair if needed, publishes/updates it

            def on_ok(_):
                self.email = email
                self._build_main_screen()

            def on_err(err):
                action_btn.set_enabled(True)
                status_label.config(text=str(err), fg=C_ERROR)

            self.run_async(work, on_ok, on_err)

        action_btn = RoundedButton(card, "Continue", do_continue)
        action_btn.pack(anchor="w")
        email_entry.bind("<Return>", lambda e: do_continue())
        email_entry.focus()

        back_link = tk.Label(card, text="← change server", font=font(9), bg="#ffffff", fg=C_TEXT_MUTED, cursor="hand2")
        back_link.pack(anchor="w", pady=(16, 0))
        back_link.bind("<Button-1>", lambda e: self._build_connect_screen())

    # ----------------------------------------------------------------
    # Screen 3: main window
    # ----------------------------------------------------------------

    def _build_main_screen(self):
        self._clear()
        self.configure(bg=C_MAIN_BG)

        root = tk.Frame(self, bg=C_MAIN_BG)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        # ---------------- Sidebar ----------------
        sidebar = tk.Frame(root, bg=C_SIDEBAR, width=280)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.pack_propagate(False)

        header = tk.Frame(sidebar, bg=C_SIDEBAR, padx=18, pady=18)
        header.pack(fill="x")
        tk.Label(header, text="Cipher Messaging", font=font(13, "bold"), bg=C_SIDEBAR, fg=C_SIDEBAR_TEXT).pack(anchor="w")

        account_row = tk.Frame(header, bg=C_SIDEBAR)
        account_row.pack(fill="x", pady=(10, 0))
        avatar = tk.Label(
            account_row, text=self.email[0].upper(), font=font(11, "bold"),
            bg=C_ACCENT, fg="#ffffff", width=3, height=1,
        )
        avatar.pack(side="left")
        acc_text = tk.Frame(account_row, bg=C_SIDEBAR)
        acc_text.pack(side="left", padx=(8, 0), fill="x", expand=True)
        tk.Label(acc_text, text=self.email, font=font(9), bg=C_SIDEBAR, fg=C_SIDEBAR_TEXT, anchor="w").pack(fill="x")
        switch_link = tk.Label(acc_text, text="Switch account", font=font(8), bg=C_SIDEBAR, fg=C_SIDEBAR_SUBTEXT, cursor="hand2", anchor="w")
        switch_link.pack(fill="x")
        switch_link.bind("<Button-1>", lambda e: self._build_login_screen())

        divider = tk.Frame(sidebar, bg=C_SIDEBAR_BORDER, height=1)
        divider.pack(fill="x")

        actions = tk.Frame(sidebar, bg=C_SIDEBAR, padx=18, pady=14)
        actions.pack(fill="x")
        new_convo_btn = RoundedButton(actions, "+  New conversation", self._open_new_conversation_dialog, bg=C_ACCENT, hover_bg=C_ACCENT_HOVER)
        new_convo_btn.pack(fill="x")

        list_label = tk.Frame(sidebar, bg=C_SIDEBAR, padx=18)
        list_label.pack(fill="x")
        tk.Label(list_label, text="CONVERSATIONS", font=font(8, "bold"), bg=C_SIDEBAR, fg=C_SIDEBAR_SUBTEXT).pack(anchor="w", pady=(4, 6))

        self.convo_scroll = ScrollableFrame(sidebar, bg=C_SIDEBAR)
        self.convo_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # ---------------- Chat area ----------------
        chat_area = tk.Frame(root, bg=C_MAIN_BG)
        chat_area.grid(row=0, column=1, sticky="nsew")
        chat_area.rowconfigure(1, weight=1)
        chat_area.columnconfigure(0, weight=1)

        self.chat_header = tk.Frame(chat_area, bg=C_HEADER_BG, height=64, highlightbackground=C_HEADER_BORDER, highlightthickness=1)
        self.chat_header.grid(row=0, column=0, sticky="ew")
        self.chat_header.pack_propagate(False)
        self.chat_title_label = tk.Label(self.chat_header, text="Select a conversation", font=font(12, "bold"), bg=C_HEADER_BG, fg=C_TEXT_DARK, padx=20)
        self.chat_title_label.pack(side="left", fill="y")

        self.messages_scroll = ScrollableFrame(chat_area, bg=C_MAIN_BG)
        self.messages_scroll.grid(row=1, column=0, sticky="nsew")
        self._show_empty_state("Select a conversation, or start a new one.")

        composer = tk.Frame(chat_area, bg=C_HEADER_BG, highlightbackground=C_HEADER_BORDER, highlightthickness=1, padx=14, pady=12)
        composer.grid(row=2, column=0, sticky="ew")
        composer.columnconfigure(0, weight=1)

        self.compose_entry = PlaceholderEntry(composer, placeholder="Type a message…")
        self.compose_entry.grid(row=0, column=0, sticky="ew", ipady=8, padx=(0, 10))
        self.compose_entry.bind("<Return>", lambda e: self._send_current_message())
        self.send_btn = RoundedButton(composer, "Send", self._send_current_message)
        self.send_btn.grid(row=0, column=1)

        self._refresh_conversations()
        self._schedule_refresh()

    def _schedule_refresh(self):
        self._refresh_conversations()
        if self.selected_conversation_id:
            self._refresh_messages(self.selected_conversation_id, preserve_scroll=True)
        self._refresh_job = self.after(REFRESH_MS, self._schedule_refresh)

    def _show_empty_state(self, text):
        self.messages_scroll.clear()
        tk.Label(
            self.messages_scroll.inner, text=text, font=font(10), bg=C_MAIN_BG, fg=C_TEXT_MUTED,
        ).pack(pady=40)

    # ---- conversations ----

    def _refresh_conversations(self):
        def work():
            return cc.list_conversations_data(self.email)

        def on_ok(convos):
            self.conversations = convos or []
            self.convo_scroll.clear()
            if not self.conversations:
                tk.Label(
                    self.convo_scroll.inner, text="No conversations yet.", font=font(9), bg=C_SIDEBAR, fg=C_SIDEBAR_SUBTEXT,
                    wraplength=220, justify="left",
                ).pack(anchor="w", padx=10, pady=10)
            for convo in self.conversations:
                self._add_conversation_row(convo)

        def on_err(err):
            self._show_error("Couldn't load conversations", err)

        self.run_async(work, on_ok, on_err)

    def _add_conversation_row(self, convo: dict):
        is_selected = convo["id"] == self.selected_conversation_id
        row_bg = C_SIDEBAR_ROW_SELECTED if is_selected else C_SIDEBAR
        row = tk.Frame(self.convo_scroll.inner, bg=row_bg, padx=10, pady=10, cursor="hand2")
        row.pack(fill="x", pady=1)

        others = [p for p in convo["participants"] if p != self.email]
        label = convo.get("name") or (", ".join(others) if others else "Just you")
        tk.Label(row, text=label, font=font(10, "bold"), bg=row_bg, fg=C_SIDEBAR_TEXT, anchor="w").pack(fill="x")

        preview = "Encrypted messages" if convo.get("last_message_preview") else "No messages yet"
        tk.Label(row, text=preview, font=font(8), bg=row_bg, fg=C_SIDEBAR_SUBTEXT, anchor="w").pack(fill="x")

        def select(_e=None):
            self._on_select_conversation(convo)

        bind_recursive(row, "<Button-1>", select)
        if not is_selected:
            def on_enter(_e):
                row.config(bg=C_SIDEBAR_ROW_HOVER)
                for child in row.winfo_children():
                    child.config(bg=C_SIDEBAR_ROW_HOVER)

            def on_leave(_e):
                row.config(bg=C_SIDEBAR)
                for child in row.winfo_children():
                    child.config(bg=C_SIDEBAR)

            bind_recursive(row, "<Enter>", on_enter)
            bind_recursive(row, "<Leave>", on_leave)

    def _open_new_conversation_dialog(self):
        participants_raw = simpledialog.askstring(
            "New conversation",
            "Participant email(s), comma-separated (not including yourself):",
            parent=self,
        )
        if not participants_raw:
            return
        participants = [p.strip() for p in participants_raw.split(",") if p.strip()]
        if not participants:
            return
        name = simpledialog.askstring("New conversation", "Conversation name (optional):", parent=self)

        def work():
            return cc.create_conversation(self.email, participants, name)

        def on_ok(new_id):
            self.selected_conversation_id = new_id
            self._refresh_conversations()
            self.chat_title_label.config(text=name or ", ".join(participants))
            self._refresh_messages(new_id)

        def on_err(err):
            self._show_error("Couldn't create conversation", err)

        self.run_async(work, on_ok, on_err)

    def _on_select_conversation(self, convo: dict):
        self.selected_conversation_id = convo["id"]
        others = [p for p in convo["participants"] if p != self.email]
        self.chat_title_label.config(text=convo.get("name") or (", ".join(others) if others else "Just you"))
        self._refresh_conversations()  # redraw sidebar so the selected row highlights
        self._refresh_messages(convo["id"])

    # ---- messages ----

    def _refresh_messages(self, conversation_id: str, preserve_scroll: bool = False):
        def work():
            return cc.read_conversation_data(self.email, conversation_id)

        def on_ok(entries):
            if self.selected_conversation_id != conversation_id:
                return  # user switched conversations while this was loading

            at_bottom = True
            if preserve_scroll:
                at_bottom = self.messages_scroll.canvas.yview()[1] >= 0.98

            self.messages_scroll.clear()
            if not entries:
                self._show_empty_state("No messages yet — say hello!")
                return

            for e in entries:
                self._add_message_bubble(e)

            if at_bottom:
                self.messages_scroll.scroll_to_bottom()

        def on_err(err):
            self._show_error("Couldn't load messages", err)

        self.run_async(work, on_ok, on_err)

    def _add_message_bubble(self, entry: dict):
        is_me = entry["sender_email"] == self.email
        row = tk.Frame(self.messages_scroll.inner, bg=C_MAIN_BG)
        row.pack(fill="x", padx=16, pady=4)

        align_frame = tk.Frame(row, bg=C_MAIN_BG)
        align_frame.pack(anchor="e" if is_me else "w")

        if not is_me:
            tk.Label(
                align_frame, text=entry["sender_email"], font=font(8, "bold"), bg=C_MAIN_BG, fg=C_TEXT_MUTED,
            ).pack(anchor="w", padx=4)

        if is_me:
            bubble = tk.Frame(align_frame, bg=C_BUBBLE_ME_BG, padx=12, pady=8)
            text_color, bg_color = C_BUBBLE_ME_TEXT, C_BUBBLE_ME_BG
        else:
            bubble = tk.Frame(
                align_frame, bg=C_BUBBLE_OTHER_BG, padx=12, pady=8,
                highlightbackground=C_BUBBLE_OTHER_BORDER, highlightthickness=1,
            )
            text_color, bg_color = C_BUBBLE_OTHER_TEXT, C_BUBBLE_OTHER_BG
        bubble.pack()

        if entry.get("error"):
            tk.Label(
                bubble, text=f"⚠ {entry['error']}", font=font(9, "italic"), bg=bg_color, fg=C_ERROR,
                wraplength=380, justify="left",
            ).pack(anchor="w")
        else:
            tk.Label(
                bubble, text=entry["plaintext"], font=font(10), bg=bg_color, fg=text_color,
                wraplength=380, justify="left",
            ).pack(anchor="w")

        ts = (entry.get("created_date") or "").replace("T", " ").replace("Z", "")
        tk.Label(
            align_frame, text=ts, font=font(7), bg=C_MAIN_BG, fg=C_TEXT_MUTED,
        ).pack(anchor="e" if is_me else "w", padx=4, pady=(2, 0))

    def _send_current_message(self):
        text = self.compose_entry.value()
        if not text or not self.selected_conversation_id:
            return
        conversation_id = self.selected_conversation_id
        self.compose_entry.delete(0, tk.END)

        def work():
            cc.send_message(self.email, conversation_id, text)

        def on_ok(_):
            self._refresh_messages(conversation_id)
            self._refresh_conversations()

        def on_err(err):
            self._show_error("Couldn't send message", err)
            self.compose_entry.insert(0, text)  # give the text back so it isn't lost

        self.run_async(work, on_ok, on_err)

    # ---- misc ----

    def _show_error(self, title: str, err: Exception):
        messagebox.showerror(title, str(err))


if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()
