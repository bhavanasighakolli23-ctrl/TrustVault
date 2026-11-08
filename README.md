# TrustVault

TrustVault is a Flask-based secure document storage and sharing application. Users can create an account, upload supported documents, share files with read or edit permissions, revoke access, and review their account activity history.

## Features
- User registration and secure password hashing
- Login and logout with session protection
- Upload PDF, TXT, DOC, DOCX, PNG, JPG, and JPEG files (10 MB maximum)
- Private document downloads
- Share documents with other registered users
- Revoke previously granted access
- Per-user activity history
- SQLite database and persistent upload storage configuration for Render

## Run locally

Install dependencies and start the app:

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

Set a strong `SECRET_KEY` environment variable before deploying publicly.

## Run tests

```bash
pytest -q
```

## Deploy on Render

The root-level `render.yaml` defines the Python web service, Gunicorn start command, generated secret key, and a persistent disk for the SQLite database and uploaded files. Connect this repository to Render and deploy the Blueprint. Confirm the persistent disk is attached before using the service for important documents.

## Security notes

Passwords are stored as Werkzeug hashes. Upload names are sanitized and stored under random server-side names. Downloads require ownership or an explicit share permission, and only document owners can grant or revoke access. Uploads are limited to 10 MB and an extension allowlist.

This is an educational application. Before production use with sensitive documents, add malware scanning, CSRF protection, rate limiting, account recovery, HTTPS enforcement, backups, and managed database/object storage.
