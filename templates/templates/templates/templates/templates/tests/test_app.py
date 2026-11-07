import io
import sys
from pathlib import Path

import pytest

# Ensure the repository root is importable when pytest collects this file.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import database
from app import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "test_trustvault.db"
    upload_path = tmp_path / "uploads"
    upload_path.mkdir()

    monkeypatch.setattr(database, "DATABASE", str(database_path))
    monkeypatch.setattr("app.UPLOAD_FOLDER", str(upload_path))
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret-key",
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    )
    database.init_db()

    with app.test_client() as test_client:
        yield test_client


def register(client, username, password="test-password-123"):
    return client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def login(client, username, password="test-password-123"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def upload_text_file(client, filename="notes.txt", content=b"TrustVault test file"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def test_registration_login_and_dashboard(client):
    response = register(client, "alice")
    assert response.status_code == 200
    assert b"Account created" in response.data

    response = login(client, "alice")
    assert response.status_code == 200
    assert b"Welcome, alice" in response.data


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_owner_can_upload_and_download_document(client):
    register(client, "alice")
    login(client, "alice")

    response = upload_text_file(client)
    assert response.status_code == 200
    assert b"Document uploaded" in response.data

    response = client.get("/dashboard")
    assert b"notes.txt" in response.data

    # The first uploaded document receives ID 1 in this isolated test database.
    response = client.get("/download/1")
    assert response.status_code == 200
    assert response.data == b"TrustVault test file"


def test_shared_user_can_download_but_unshared_user_cannot(client):
    register(client, "alice")
    register(client, "bob")
    register(client, "charlie")

    login(client, "alice")
    upload_text_file(client)
    response = client.post(
        "/share/1",
        data={"user_id": "2", "permission": "read"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    client.get("/logout")
    login(client, "bob")
    assert client.get("/download/1").status_code == 200

    client.get("/logout")
    login(client, "charlie")
    assert client.get("/download/1").status_code == 403


def test_audit_history_is_limited_to_signed_in_user(client):
    register(client, "alice")
    register(client, "bob")

    login(client, "alice")
    upload_text_file(client)
    client.get("/logout")

    login(client, "bob")
    response = client.get("/audit")
    assert response.status_code == 200
    assert b"upload" not in response.data


def test_disallowed_file_extension_is_rejected(client):
    register(client, "alice")
    login(client, "alice")

    response = upload_text_file(client, filename="malware.exe")
    assert response.status_code == 200
    assert b"File type not allowed" in response.data

def test_shared_editor_cannot_change_sharing_or_revoke_access(client):
    register(client, "alice")
    register(client, "bob")
    register(client, "charlie")

    login(client, "alice")
    upload_text_file(client)
    client.post(
        "/share/1",
        data={"user_id": "2", "permission": "edit"},
        follow_redirects=True,
    )
    client.post(
        "/share/1",
        data={"user_id": "3", "permission": "read"},
        follow_redirects=True,
    )

    client.get("/logout")
    login(client, "bob")
    # Edit permission allows document access, but only the owner manages sharing.
    assert client.post(
        "/share/1",
        data={"user_id": "3", "permission": "edit"},
    ).status_code == 403
    assert client.post("/revoke/1/3").status_code == 403
