import hashlib
import os
import pickle
import re
import runpy

import jwt
import pytest

from conftest import ROOT

pytestmark = pytest.mark.security

CALLED = []


def record(value):
    CALLED.append(value)
    return value


class Payload:
    def __reduce__(self):
        return (record, ("executed",))


@pytest.fixture(autouse=True)
def reset_called():
    CALLED.clear()


@pytest.mark.xfail(strict=True, reason="CWE-89: f-string SQL in app.py:21")
def test_sql_injection_returns_no_rows(client, shop_db):
    response = client.get("/user", query_string={"name": "x' OR '1'='1"})
    assert "alice" not in response.get_data(as_text=True)


@pytest.mark.xfail(strict=True, reason="CWE-78: shell=True in app.py:28")
def test_command_injection_is_not_executed(client):
    response = client.get("/ping", query_string={"host": "127.0.0.1; echo INJECTED_MARKER"})
    assert b"INJECTED_MARKER" not in response.get_data()


@pytest.mark.xfail(strict=True, reason="CWE-22: unchecked path in app.py:33")
def test_path_traversal_is_blocked(client, sent_paths):
    client.get("/download", query_string={"file": "../../../etc/passwd"})
    assert all(os.path.normpath(p).startswith("/var/app/uploads/") for p in sent_paths)


@pytest.mark.xfail(strict=True, reason="CWE-79: unescaped HTML in app.py:38")
def test_reflected_input_is_escaped(client):
    response = client.get("/hello", query_string={"name": "<script>alert(1)</script>"})
    assert "<script>" not in response.get_data(as_text=True)


@pytest.mark.xfail(strict=True, reason="CWE-95: eval in app.py:43")
def test_eval_does_not_execute_code(client):
    response = client.get("/calc", query_string={"expr": "__import__('os').getpid()"})
    assert str(os.getpid()) not in response.get_data(as_text=True)


@pytest.mark.xfail(strict=True, reason="CWE-918: user URL fetched in app.py:48")
def test_ssrf_blocks_internal_addresses(client, http_calls):
    client.get("/fetch", query_string={"url": "http://169.254.169.254/latest/meta-data/"})
    assert http_calls == []


@pytest.mark.xfail(strict=True, reason="CWE-295: verify=False in app.py:48")
def test_tls_verification_stays_enabled(client, http_calls):
    client.get("/fetch", query_string={"url": "https://example.com"})
    assert http_calls[0]["kwargs"].get("verify", True) is not False


@pytest.mark.xfail(strict=True, reason="CWE-601: unvalidated redirect in app.py:54")
def test_open_redirect_is_rejected(client):
    response = client.get("/go", query_string={"next": "https://evil.example/"})
    assert "evil.example" not in response.headers.get("Location", "")


@pytest.mark.xfail(strict=True, reason="CWE-502: pickle.loads in app.py:59")
def test_pickle_payload_is_not_executed(client):
    client.post("/session", data=pickle.dumps(Payload()))
    assert CALLED == []


@pytest.mark.xfail(strict=True, reason="CWE-502: yaml.Loader in app.py:64")
def test_yaml_python_tags_are_not_executed(client):
    response = client.post("/config", data="!!python/object/apply:os.getpid []")
    assert str(os.getpid()) not in response.get_data(as_text=True)


@pytest.mark.xfail(strict=True, reason="CWE-328: MD5 in app.py:68")
def test_password_hash_is_not_plain_md5(app_module):
    assert app_module.hash_password("password") != hashlib.md5(b"password").hexdigest()


@pytest.mark.xfail(strict=True, reason="CWE-916: unsalted hash in app.py:68")
def test_password_hash_is_salted(app_module):
    assert app_module.hash_password("same") != app_module.hash_password("same")


@pytest.mark.xfail(strict=True, reason="CWE-347: no signature check in app.py:72")
def test_forged_jwt_is_rejected(app_module):
    forged = jwt.encode({"sub": "admin"}, "attacker-key-0123456789-0123456789", algorithm="HS256")
    with pytest.raises(Exception):
        app_module.read_claims(forged)


@pytest.mark.xfail(strict=True, reason="CWE-489: debug=True in app.py:76")
def test_debug_mode_is_off_when_run_directly(monkeypatch):
    import flask

    captured = {}
    monkeypatch.setattr(flask.Flask, "run", lambda self, *a, **kw: captured.update(kw))
    runpy.run_path(str(ROOT / "app.py"), run_name="__main__")
    assert captured.get("debug") is not True


@pytest.mark.xfail(strict=True, reason="CWE-798: literals in app.py:12 and app.py:14")
@pytest.mark.parametrize("pattern", [r"secret_key\s*=\s*[\"']", r"PASSWORD\s*=\s*[\"']"])
def test_app_source_has_no_hardcoded_credentials(pattern):
    assert not re.search(pattern, (ROOT / "app.py").read_text())


@pytest.mark.xfail(strict=True, reason="CWE-798: plaintext secrets in config files")
@pytest.mark.parametrize("name", ["config.yaml", ".env", "settings.ini"])
def test_config_files_have_no_plaintext_secrets(name):
    text = (ROOT / name).read_text()
    assert not re.search(r"(?im)^\s*\w*(password|secret)\w*\s*[:=]\s*[^\s$]+", text)


@pytest.mark.xfail(strict=True, reason="CWE-250: no USER in Dockerfile")
def test_dockerfile_does_not_run_as_root():
    assert re.search(r"(?im)^USER\s+(?!root\b)\S+", (ROOT / "Dockerfile").read_text())


@pytest.mark.xfail(strict=True, reason="CWE-1104: end-of-life python:3.8 in Dockerfile:1")
def test_dockerfile_uses_supported_python():
    match = re.search(r"(?im)^FROM\s+python:(\d+)\.(\d+)", (ROOT / "Dockerfile").read_text())
    assert (int(match.group(1)), int(match.group(2))) >= (3, 11)
