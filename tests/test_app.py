import io
import pytest

import database
from app import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "trustvault-test.db"
    upload_path = tmp_path / "uploads"
    upload_path.mkdir()
    monkeypatch.setattr(database, "DATABASE", str(db_path))
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        UPLOAD_FOLDER=str(upload_path),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    )
    database.init_db()
    with app.test_client() as test_client:
        yield test_client


def register(client, username, password="password-123"):
    return client.post("/register", data={"username": username, "password": password}, follow_redirects=True)


def login(client, username, password="password-123"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def upload(client, filename="notes.txt", content=b"TrustVault test file"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def test_home_and_auth_pages_render(client):
    assert client.get("/").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/register").status_code == 200


def test_register_login_and_dashboard(client):
    response = register(client, "alice")
    assert b"Account created" in response.data
    response = login(client, "alice")
    assert response.status_code == 200
    assert b"Welcome, alice" in response.data


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_owner_can_upload_and_download(client):
    register(client, "alice")
    login(client, "alice")
    response = upload(client)
    assert b"Document uploaded" in response.data
    response = client.get("/download/1")
    assert response.status_code == 200
    assert response.data == b"TrustVault test file"


def test_share_and_revoke_access(client):
    register(client, "alice")
    register(client, "bob")
    login(client, "alice")
    upload(client)
    response = client.post("/share/1", data={"user_id": "2", "permission": "read"})
    assert response.status_code == 302
    client.post("/logout")
    login(client, "bob")
    assert client.get("/download/1").status_code == 200
    client.post("/logout")
    login(client, "alice")
    assert client.post("/revoke/1/2").status_code == 302
    client.post("/logout")
    login(client, "bob")
    assert client.get("/download/1").status_code == 403


def test_unshared_user_cannot_download(client):
    register(client, "alice")
    register(client, "charlie")
    login(client, "alice")
    upload(client)
    client.post("/logout")
    login(client, "charlie")
    assert client.get("/download/1").status_code == 403


def test_disallowed_extension_is_rejected(client):
    register(client, "alice")
    login(client, "alice")
    response = upload(client, filename="malware.exe")
    assert b"File type not allowed" in response.data


def test_audit_is_private_to_current_user(client):
    register(client, "alice")
    register(client, "bob")
    login(client, "alice")
    upload(client)
    client.post("/logout")
    login(client, "bob")
    response = client.get("/audit")
    assert response.status_code == 200
    assert b"upload" not in response.data
