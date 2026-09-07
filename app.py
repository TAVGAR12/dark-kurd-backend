import os
import re
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, render_template, redirect, url_for, session, abort, jsonify, Response
from werkzeug.middleware.proxy_fix import ProxyFix
import hmac

app = Flask(__name__)
# Render sits behind a trusted reverse proxy; use its forwarded client IP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("APP_SECRET", "change-this-secret")
DB = os.environ.get("LOG_DB", "security_logs.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

SUSPICIOUS_PATTERNS = [
    r"\.\./", r"%2e%2e", r"<script", r"union\s+select",
    r"wp-admin", r"phpmyadmin", r"\.env", r"\.git/",
    r"etc/passwd", r"cmd\.exe", r"powershell", r"base64"
]

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""CREATE TABLE IF NOT EXISTS request_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        ip TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        user_agent TEXT,
        status INTEGER,
        suspicious INTEGER DEFAULT 0,
        reason TEXT
    )""")
    con.commit()
    con.close()

def client_ip():
    # Direct-server deployment: use the peer IP. Do not trust X-Forwarded-For
    # unless you intentionally configure a trusted reverse proxy.
    return request.remote_addr or "unknown"

def suspicious_reason(path, method):
    hay = f"{method} {path}".lower()
    hits = [p for p in SUSPICIOUS_PATTERNS if re.search(p, hay, re.I)]
    if hits:
        return "suspicious-path-pattern"
    if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
        return "unusual-http-method"
    return None

def rate_reason(ip):
    # Detection only: flag bursts, never automatically block.
    con = db()
    row = con.execute(
        "SELECT COUNT(*) c FROM request_logs WHERE ip=? AND ts >= datetime('now','-1 minute')",
        (ip,)
    ).fetchone()
    con.close()
    return "high-request-rate" if row["c"] >= 60 else None

def log_request(status=200):
    ip = client_ip()
    reason = suspicious_reason(request.path, request.method) or rate_reason(ip)
    con = db()
    con.execute("""INSERT INTO request_logs
        (ts,ip,method,path,user_agent,status,suspicious,reason)
        VALUES(?,?,?,?,?,?,?,?)""",
        (datetime.now(timezone.utc).isoformat(), ip, request.method,
         request.path[:2000], request.headers.get("User-Agent","")[:1000],
         status, 1 if reason else 0, reason))
    con.commit()
    con.close()

@app.before_request
def before():
    init_db()

@app.after_request
def after(response):
    try:
        log_request(response.status_code)
    except Exception:
        pass
    return response

@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n", mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap():
    base = request.url_root.rstrip("/")
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{base}/</loc></url></urlset>'
    return Response(xml, mimetype="application/xml")

@app.route("/")
def home():
    return render_template("index.html")

@app.errorhandler(404)
def not_found(e):
    # after_request records the 404.
    return "Not Found", 404

@app.errorhandler(500)
def server_error(e):
    return "Internal Server Error", 500

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not ADMIN_PASSWORD:
            abort(503, description="Set ADMIN_PASSWORD on the server first.")
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if ADMIN_PASSWORD and hmac.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session["admin"] = True
            return redirect(url_for("admin"))
        return render_template("login.html", error="Wrong password")
    return render_template("login.html", error=None)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin():
    con = db()
    recent = con.execute("""SELECT * FROM request_logs
                            ORDER BY id DESC LIMIT 100""").fetchall()
    counts = con.execute("""SELECT ip, COUNT(*) AS requests
                            FROM request_logs
                            GROUP BY ip ORDER BY requests DESC LIMIT 50""").fetchall()
    suspicious = con.execute("""SELECT * FROM request_logs
                               WHERE suspicious=1
                               ORDER BY id DESC LIMIT 100""").fetchall()
    con.close()
    total = con.execute("SELECT COUNT(*) c FROM request_logs").fetchone()["c"]
    bad = con.execute("SELECT COUNT(*) c FROM request_logs WHERE suspicious=1").fetchone()["c"]
    unique = con.execute("SELECT COUNT(DISTINCT ip) c FROM request_logs").fetchone()["c"]
    return render_template("admin.html", recent=recent, counts=counts, suspicious=suspicious, total=total, bad=bad, unique=unique)

@app.route("/admin/api/summary")
@admin_required
def summary():
    con = db()
    total = con.execute("SELECT COUNT(*) c FROM request_logs").fetchone()["c"]
    bad = con.execute("SELECT COUNT(*) c FROM request_logs WHERE suspicious=1").fetchone()["c"]
    unique = con.execute("SELECT COUNT(DISTINCT ip) c FROM request_logs").fetchone()["c"]
    con.close()
    return jsonify(total_requests=total, suspicious_requests=bad, unique_ips=unique)

if __name__ == "__main__":
    init_db()
    # For production, run behind a real WSGI server such as gunicorn/waitress.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
