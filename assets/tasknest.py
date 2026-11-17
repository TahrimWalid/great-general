#!/usr/bin/env python3
"""TaskNest: a tiny to-do web app with planted bugs, for calibrating QA runs.

  python3 tasknest.py [--port 8765] [--clean]

Without --clean it contains six planted bugs (listed in the skill's
evals/web-seeded-bugs/case.yaml; don't show that file to the agent under test). With --clean they are all fixed, so a
run against it measures false alarms. Standard library only; all data is kept
in memory and lost on exit.

If QA_USER_EMAIL and QA_USER_PASSWORD are set, that account exists at start-up
with two tasks.
"""
from __future__ import annotations

import argparse
import html
import os
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SEEDED = True
MAX_TITLE = 80
USERS: dict[str, dict] = {}      # email -> {name, password, tasks: [{id,title}], created_count}
SESSIONS: dict[str, str] = {}    # sid -> email
NEXT_ID = [1]

CSS = """
body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#222}
nav a{margin-right:1rem} .err{color:#b00020} .btn{padding:.5rem 1rem;border:1px solid #333;background:#fff;cursor:pointer}
input[type=text],input[type=email],input[type=password]{padding:.4rem;width:100%;max-width:360px;box-sizing:border-box}
li{margin:.3rem 0}
"""
SEEDED_CSS = "@media (max-width:500px){.create-btn{display:none}}"


def page(title: str, body: str, email: str | None = None) -> str:
    nav = ('<a href="/dashboard">Dashboard</a><a href="/profile">Profile</a><a href="/help">Help</a>'
           '<form method="post" action="/logout" style="display:inline"><button class="btn">Log out</button></form>'
           if email else '<a href="/">Home</a><a href="/login">Log in</a><a href="/signup">Sign up</a><a href="/help">Help</a>')
    css = CSS + (SEEDED_CSS if SEEDED else "")
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)} · TaskNest</title><style>{css}</style></head><body><nav>{nav}</nav><main>{body}</main></body></html>")


def new_task(user: dict, title: str) -> None:
    user["tasks"].append({"id": NEXT_ID[0], "title": title})
    NEXT_ID[0] += 1
    user["created_count"] += 1


class App(BaseHTTPRequestHandler):
    server_version = "TaskNest/1.0"

    def log_message(self, *args):  # keep the console quiet
        pass

    # --- helpers -----------------------------------------------------------------
    def user(self) -> tuple[str | None, dict | None]:
        c = SimpleCookie(self.headers.get("Cookie", ""))
        sid = c["sid"].value if "sid" in c else None
        email = SESSIONS.get(sid) if sid else None
        return email, USERS.get(email) if email else None

    def form(self) -> dict[str, str]:
        n = int(self.headers.get("Content-Length", 0) or 0)
        data = parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True)
        return {k: v[0] for k, v in data.items()}

    def send(self, body: str, status: int = 200, ctype: str = "text/html; charset=utf-8", headers: dict | None = None):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, to: str, headers: dict | None = None):
        self.send_response(303)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def login_session(self, email: str):
        sid = secrets.token_urlsafe(16)
        SESSIONS[sid] = email
        self.redirect("/dashboard", {"Set-Cookie": f"sid={sid}; HttpOnly; SameSite=Lax; Path=/"})

    def dashboard(self, email: str, user: dict, error: str = "", keep: str = "", status: int = 200):
        count = user["created_count"] if SEEDED else len(user["tasks"])
        items = "".join(
            f'<li>{html.escape(t["title"])} <form method=post action="/tasks/{t["id"]}/delete" style="display:inline">'
            f'<button class=btn onclick="return confirm(\'Delete this task?\')">Delete</button></form></li>'
            for t in user["tasks"]) or "<p>No tasks yet. Add your first one below.</p>"
        value = "" if SEEDED else html.escape(keep, quote=True)
        err = f'<p class=err role=alert>{html.escape(error)}</p>' if error else ""
        body = (f"<h1>Your tasks</h1><p>You have {count} task{'s' if count != 1 else ''}.</p><ul>{items}</ul>"
                f"<h2>Add a task</h2>{err}<form method=post action=/tasks><label>Title<br>"
                f"<input type=text name=title value=\"{value}\"></label><br><br>"
                f"<button class='btn create-btn'>Create task</button></form>"
                f'<p><a href="/tasks/export">Export my tasks (CSV)</a></p>')
        self.send(page("Dashboard", body, email), status)

    # --- routes --------------------------------------------------------------------
    def do_GET(self):
        self.safely(self.get)

    def do_POST(self):
        self.safely(self.post)

    def safely(self, handler):
        # Like a real framework: an unhandled error becomes a generic 500 page.
        try:
            handler()
        except Exception:
            self.send(page("Error", "<h1>Something went wrong</h1><p>Please try again later.</p>"), 500)

    def get(self):
        path = urlparse(self.path).path
        email, user = self.user()
        if path == "/":
            return self.send(page("Welcome", "<h1>TaskNest</h1><p>The simplest way to keep track of what to do next.</p>"
                                  '<p><a class=btn href="/signup">Get started, it’s free</a></p>', email))
        if path == "/help":
            return self.send(page("Help", "<h1>Help</h1><p>Sign up, then add tasks from your dashboard. "
                                  "Delete a task when it’s done. Export your tasks as CSV from the dashboard.</p>", email))
        if path == "/signup":
            return self.send(page("Sign up", self.signup_form()))
        if path == "/login":
            return self.send(page("Log in", self.login_form()))
        if path == "/dashboard":
            if not user:
                return self.redirect("/login")
            return self.dashboard(email, user)
        if path == "/profile":
            if not user:
                return self.redirect("/login")
            initial = user["name"].strip()[0].upper() if SEEDED else (user["name"].strip()[:1].upper() or "?")
            return self.send(page("Profile", f"<h1>Profile</h1><p style='font-size:2rem'>{html.escape(initial)}</p>"
                                  f"<p>Name: {html.escape(user['name'])}</p><p>Email: {html.escape(email)}</p>", email))
        if path == "/tasks/export":
            if not user and not SEEDED:
                return self.redirect("/login")
            rows = ["owner,title"]
            owners = USERS.items() if (SEEDED and not user) else [(email, user)]
            for owner, u in owners:
                rows += [f'{owner},"{t["title"].replace(chr(34), chr(34) * 2)}"' for t in u["tasks"]]
            return self.send("\n".join(rows) + "\n", ctype="text/csv; charset=utf-8")
        self.send(page("Not found", "<h1>Page not found</h1><p><a href='/'>Go home</a></p>", email), 404)

    def post(self):
        path = urlparse(self.path).path
        email, user = self.user()
        f = self.form()
        if path == "/signup":
            name, mail, pw = f.get("name", ""), f.get("email", "").strip().lower(), f.get("password", "")
            errors = []
            if not name.strip() and not SEEDED:
                errors.append("Please enter your name.")
            if "@" not in mail:
                errors.append("Please enter a valid email address.")
            elif mail in USERS:
                errors.append("An account with this email already exists. Log in instead?")
            if len(pw) < 8:
                errors.append("Password must be at least 8 characters.")
            if errors:
                return self.send(page("Sign up", self.signup_form(errors, name, mail)), 400)
            USERS[mail] = {"name": name, "password": pw, "tasks": [], "created_count": 0}
            return self.login_session(mail)
        if path == "/login":
            mail, pw = f.get("email", "").strip().lower(), f.get("password", "")
            if mail in USERS and USERS[mail]["password"] == pw:
                return self.login_session(mail)
            return self.send(page("Log in", self.login_form("Email or password is incorrect.", mail)), 401)
        if path == "/logout":
            c = SimpleCookie(self.headers.get("Cookie", ""))
            if "sid" in c:
                SESSIONS.pop(c["sid"].value, None)
            return self.redirect("/", {"Set-Cookie": "sid=; Max-Age=0; Path=/"})
        if not user:
            return self.redirect("/login")
        if path == "/tasks":
            title = f.get("title", "").strip()
            if not title:
                return self.dashboard(email, user, "Please enter a task title.", title, 400)
            if len(title) > MAX_TITLE:
                return self.dashboard(email, user, f"Title is too long (max {MAX_TITLE} characters).", title, 400)
            new_task(user, title)
            return self.redirect("/dashboard")
        if path.startswith("/tasks/") and path.endswith("/delete"):
            try:
                tid = int(path.split("/")[2])
            except ValueError:
                return self.send(page("Not found", "<h1>Task not found</h1>", email), 404)
            if SEEDED:
                for u in USERS.values():  # looks up the task in every account, not just the caller's
                    u["tasks"] = [t for t in u["tasks"] if t["id"] != tid]
            else:
                user["tasks"] = [t for t in user["tasks"] if t["id"] != tid]
            return self.redirect("/dashboard")
        self.send(page("Not found", "<h1>Page not found</h1>", email), 404)

    # --- forms ---------------------------------------------------------------------
    @staticmethod
    def signup_form(errors: list[str] | None = None, name: str = "", mail: str = "") -> str:
        err = "".join(f"<p class=err role=alert>{html.escape(e)}</p>" for e in errors or [])
        return (f"<h1>Create your account</h1>{err}<form method=post action=/signup>"
                f"<label>Name<br><input type=text name=name value=\"{html.escape(name, quote=True)}\"></label><br><br>"
                f"<label>Email<br><input type=email name=email value=\"{html.escape(mail, quote=True)}\"></label><br><br>"
                "<label>Password (8+ characters)<br><input type=password name=password></label><br><br>"
                "<button class=btn>Sign up</button></form><p>Already have an account? <a href='/login'>Log in</a></p>")

    @staticmethod
    def login_form(error: str = "", mail: str = "") -> str:
        err = f"<p class=err role=alert>{html.escape(error)}</p>" if error else ""
        return (f"<h1>Log in</h1>{err}<form method=post action=/login>"
                f"<label>Email<br><input type=email name=email value=\"{html.escape(mail, quote=True)}\"></label><br><br>"
                "<label>Password<br><input type=password name=password></label><br><br>"
                "<button class=btn>Log in</button></form><p>New here? <a href='/signup'>Create an account</a></p>")


def main() -> None:
    global SEEDED
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--clean", action="store_true", help="no planted bugs (for false-alarm calibration)")
    a = ap.parse_args()
    SEEDED = not a.clean
    qa_mail, qa_pw = os.environ.get("QA_USER_EMAIL"), os.environ.get("QA_USER_PASSWORD")
    if qa_mail and qa_pw:
        USERS[qa_mail.lower()] = {"name": "QA User", "password": qa_pw, "tasks": [], "created_count": 0}
        new_task(USERS[qa_mail.lower()], "Try TaskNest")
        new_task(USERS[qa_mail.lower()], "Invite a teammate")
    print(f"TaskNest on http://127.0.0.1:{a.port} ({'clean build' if a.clean else 'planted bugs'})", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), App).serve_forever()


if __name__ == "__main__":
    main()
