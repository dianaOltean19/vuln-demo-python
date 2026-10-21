def test_user_lookup_returns_matching_row(client, shop_db):
    response = client.get("/user?name=alice")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "alice" in body
    assert "bob" not in body


def test_user_lookup_unknown_name_returns_empty_list(client, shop_db):
    response = client.get("/user?name=nobody")
    assert response.get_data(as_text=True) == "[]"


def test_hello_greets_by_name(client):
    response = client.get("/hello?name=Diana")
    assert "Hello Diana" in response.get_data(as_text=True)


def test_hello_without_name_still_responds(client):
    response = client.get("/hello")
    assert response.status_code == 200
    assert "Hello" in response.get_data(as_text=True)


def test_calc_adds_numbers(client):
    response = client.get("/calc?expr=2%2B3")
    assert response.get_data(as_text=True) == "5"


def test_calc_defaults_to_zero(client):
    response = client.get("/calc")
    assert response.get_data(as_text=True) == "0"


def test_redirect_follows_relative_path(client):
    response = client.get("/go?next=/home")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/home")


def test_redirect_defaults_to_root(client):
    response = client.get("/go")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_download_serves_file_from_uploads_directory(client, sent_paths):
    response = client.get("/download?file=report.txt")
    assert response.status_code == 200
    assert sent_paths == ["/var/app/uploads/report.txt"]


def test_fetch_returns_remote_body(client, http_calls):
    response = client.get("/fetch?url=https://example.com")
    assert response.get_data(as_text=True) == "remote body"
    assert http_calls[0]["url"] == "https://example.com"


def test_ping_returns_command_output(client, app_module, monkeypatch):
    monkeypatch.setattr(app_module.subprocess, "check_output", lambda *a, **k: b"pong")
    response = client.get("/ping?host=127.0.0.1")
    assert response.status_code == 200
    assert response.get_data(as_text=True) == "pong"


def test_config_loads_simple_yaml(client):
    response = client.post("/config", data="a: 1")
    assert response.get_data(as_text=True) == "{'a': 1}"


def test_hash_password_returns_non_empty_string(app_module):
    assert isinstance(app_module.hash_password("secret"), str)
    assert app_module.hash_password("secret")


def test_hash_password_differs_per_password(app_module):
    assert app_module.hash_password("one") != app_module.hash_password("two")
