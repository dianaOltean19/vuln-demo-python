import ast
import json
import os
import hashlib
import re
import shlex
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, redirect, request, send_file, render_template, url_for
from markupsafe import escape
from urllib.parse import urlparse, urlunparse
from werkzeug.utils import secure_filename
from pathlib import Path

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

ALLOWED_HOSTS = ["example.com", "api.example.com"]
ALLOWED_SCHEMES = ["http", "https"]


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("shop.db")
    cur = conn.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]*$", host):
        return "Invalid host", 400
    return subprocess.check_output(["ping", "-c", "1", host])


@app.route("/download")
def download():
    filename = secure_filename(request.args.get("file", ""))
    if not filename:
        return "Invalid file", 400
    file_path = (Path("/var/app/uploads") / filename).resolve()
    if not file_path.is_relative_to(Path("/var/app/uploads").resolve()):
        return "Access denied", 403
    return send_file(file_path)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template("hello.html", name=name)


@app.route("/calc")
def calc():
    try:
        return str(ast.literal_eval(request.args.get("expr", "0")))
    except (ValueError, SyntaxError):
        return "Invalid expression", 400


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "URL required", 400
    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port
    path = parsed.path
    if not scheme or not host:
        return "Invalid URL format", 400
    if scheme not in ALLOWED_SCHEMES:
        return "URL scheme not allowed", 400
    if host.lower() not in [h.lower() for h in ALLOWED_HOSTS]:
        return "Host not allowed", 400
    safe_url = urlunparse((scheme, netloc := f"{host}:{port}" if port else host, path, "", "", ""))
    resp = requests.get(safe_url, verify=True)
    return resp.text


@app.route("/go")
def go():
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)
    if parsed.netloc:
        return redirect(url_for("hello"))
    return redirect(next_url)


@app.route("/session", methods=["POST"])
def load_session():
    return str(json.loads(request.get_data()))


@app.route("/config", methods=["POST"])
def load_config():
    return str(yaml.safe_load(request.get_data()))


def hash_password(password):
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()


def read_claims(token):
    return jwt.decode(token, app.secret_key, algorithms=["HS256"])


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
