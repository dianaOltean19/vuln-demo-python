import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


class FakeResponse:
    text = "remote body"


@pytest.fixture
def app_module():
    import app

    return app


@pytest.fixture
def client(app_module):
    app_module.app.config["TESTING"] = True
    app_module.app.config["PROPAGATE_EXCEPTIONS"] = False
    return app_module.app.test_client()


@pytest.fixture
def shop_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    conn = sqlite3.connect("shop.db")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
    conn.executemany(
        "INSERT INTO users (name, secret) VALUES (?, ?)",
        [("alice", "alice-secret"), ("bob", "bob-secret")],
    )
    conn.commit()
    conn.close()


@pytest.fixture
def sent_paths(monkeypatch, app_module):
    paths = []
    monkeypatch.setattr(
        app_module, "send_file", lambda path, *a, **k: paths.append(path) or "sent"
    )
    return paths


@pytest.fixture
def http_calls(monkeypatch, app_module):
    calls = []

    def fake_get(url, **kwargs):
        calls.append({"url": url, "kwargs": kwargs})
        return FakeResponse()

    monkeypatch.setattr(app_module.requests, "get", fake_get)
    return calls
