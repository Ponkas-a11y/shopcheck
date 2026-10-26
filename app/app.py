import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import checks

DB_PATH = os.environ.get("DB_PATH", "/data/shopcheck.db")
REG_CODE = os.environ.get("REGISTRATION_CODE", "")
RATE = int(os.environ.get("RATE_LIMIT_PER_HOUR", "20"))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
)

SCHEMA = """
create table if not exists users(id integer primary key, username text unique not null,
  pw_hash text not null, is_admin integer not null default 0, created real not null);
create table if not exists checks(id integer primary key, user_id integer not null references users(id),
  url text not null, domain text not null, score integer not null, verdict text not null,
  result text not null, created real not null);
create index if not exists ix_checks_user on checks(user_id, created);
"""


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as c:
        c.executescript(SCHEMA)


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


@app.template_filter("dt")
def fmt_dt(ts):
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")


app.jinja_env.globals["csrf"] = lambda: session.get("csrf", "")


@app.before_request
def load_user_and_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    if request.method == "POST" and not secrets.compare_digest(request.form.get("csrf", ""), session["csrf"]):
        abort(400)
    g.user = None
    if "uid" in session:
        g.user = db().execute("select * from users where id=?", (session["uid"],)).fetchone()


def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not g.user:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return w


FAILS = {}


def throttled(ip):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 600]
    return len(FAILS[ip]) >= 8


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        if throttled(ip):
            flash("Zu viele Fehlversuche. Bitte in ein paar Minuten erneut versuchen.")
            return render_template("auth.html", mode="login")
        u = db().execute("select * from users where username=?", (request.form.get("username", "").strip(),)).fetchone()
        if u and check_password_hash(u["pw_hash"], request.form.get("password", "")):
            session.clear()
            session.permanent = True
            session["uid"] = u["id"]
            return redirect(url_for("index"))
        FAILS.setdefault(ip, []).append(time.time())
        flash("Benutzername oder Passwort falsch.")
    return render_template("auth.html", mode="login")


@app.route("/register", methods=["GET", "POST"])
def register():
    first = db().execute("select count(*) from users").fetchone()[0] == 0
    if request.method == "POST":
        name, pw = request.form.get("username", "").strip(), request.form.get("password", "")
        code = request.form.get("code", "")
        if not first and (not REG_CODE or not secrets.compare_digest(code, REG_CODE)):
            flash("Registrierung nicht möglich: falscher oder fehlender Einladungscode.")
        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", name):
            flash("Benutzername: 3–32 Zeichen (Buchstaben, Ziffern, _ . -).")
        elif len(pw) < 10:
            flash("Passwort: mindestens 10 Zeichen.")
        else:
            try:
                db().execute("insert into users(username,pw_hash,is_admin,created) values(?,?,?,?)",
                             (name, generate_password_hash(pw), int(first), time.time()))
                db().commit()
                flash("Account erstellt – bitte anmelden.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Benutzername ist schon vergeben.")
    return render_template("auth.html", mode="register", first=first, need_code=not first)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    if g.user["is_admin"]:
        rows = db().execute("select c.*, u.username from checks c join users u on u.id=c.user_id order by c.id desc limit 50").fetchall()
    else:
        rows = db().execute("select c.*, ? as username from checks c where user_id=? order by id desc limit 50",
                            (g.user["username"], g.user["id"])).fetchall()
    return render_template("index.html", rows=rows)


@app.post("/check")
@login_required
def check():
    n = db().execute("select count(*) from checks where user_id=? and created>?", (g.user["id"], time.time() - 3600)).fetchone()[0]
    if n >= RATE:
        flash(f"Limit erreicht ({RATE} Prüfungen pro Stunde).")
        return redirect(url_for("index"))
    try:
        res = checks.run_checks(request.form.get("url", ""))
    except ValueError as e:
        flash(str(e))
        return redirect(url_for("index"))
    except Exception:
        app.logger.exception("Prüfung fehlgeschlagen")
        flash("Die Prüfung ist unerwartet fehlgeschlagen.")
        return redirect(url_for("index"))
    cur = db().execute("insert into checks(user_id,url,domain,score,verdict,result,created) values(?,?,?,?,?,?,?)",
                       (g.user["id"], res["url"], res["domain"], res["score"], res["verdict"], json.dumps(res), time.time()))
    db().commit()
    return redirect(url_for("result", cid=cur.lastrowid))


@app.route("/result/<int:cid>")
@login_required
def result(cid):
    row = db().execute("select * from checks where id=?", (cid,)).fetchone()
    if not row or (row["user_id"] != g.user["id"] and not g.user["is_admin"]):
        abort(404)
    return render_template("result.html", r=json.loads(row["result"]), created=row["created"])
