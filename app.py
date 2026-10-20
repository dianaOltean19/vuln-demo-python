import hashlib
import pickle
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, redirect, request, send_file

app = Flask(__name__)
app.secret_key = "super-secret-key-123"

DB_PASSWORD = "Winter2025!"


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("shop.db")
    cur = conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/download")
def download():
    return send_file("/var/app/uploads/" + request.args.get("file", ""))


@app.route("/hello")
def hello():
    return "<h1>Hello " + request.args.get("name", "") + "</h1>"


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))


@app.route("/fetch")
def fetch():
    resp = requests.get(request.args.get("url", ""), verify=False)
    return resp.text


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))


@app.route("/session", methods=["POST"])
def load_session():
    return str(pickle.loads(request.get_data()))


@app.route("/config", methods=["POST"])
def load_config():
    return str(yaml.load(request.get_data(), Loader=yaml.Loader))


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def read_claims(token):
    return jwt.decode(token, options={"verify_signature": False})


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
