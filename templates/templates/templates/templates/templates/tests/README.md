# TrustVault

TrustVault is a Flask web application for securely uploading, managing, downloading, and sharing documents with other registered users.

## Features

- User registration and login with hashed passwords
- Upload PDF, TXT, DOC, DOCX, PNG, JPG, and JPEG files (10 MB maximum)
- Private document ownership
- Share documents with read or edit permissions
- Download access checks
- Per-user audit history
- SQLite database

## Project structure

```text
trustvault/
├── app.py
├── database.py
├── requirements.txt
├── render.yaml
├── static/
│   └── style.css
└── templates/
    ├── index.html
    ├── login.html
    ├── dashboard.html
    └── audit.html


## Run locally

1. Install Python 3.10 or later.
2. Clone this repository:
   bash
   git clone https://github.com/midasalabhanupriya-cloud/trustvault.git
   cd trustvault
   
3. Create and activate a virtual environment:
   bash
   python -m venv venv
   
   Windows:
   bash
   venv\\Scripts\\activate
   
   macOS/Linux:
   bash
   source venv/bin/activate
   
4. Install dependencies:
   bash
   pip install -r requirements.txt
   
5. Set a strong secret key before running the app.

   Windows PowerShell:
   powershell
   $env:SECRET_KEY = "replace-with-a-long-random-secret"
   

   macOS/Linux:
   bash
   export SECRET_KEY="replace-with-a-long-random-secret"
   
6. Start the application:
   bash
   python app.py
   
7. Open http://127.0.0.1:5000 in your browser.

## Run automated tests

Install the project dependencies (including pytest) and run:

bash
pytest -q


GitHub Actions runs this test suite automatically when changes are pushed to `main` or a pull request targets `main`. The tests use a temporary SQLite database and temporary upload folder, so they do not use real user data.

## Deploy on Render

This repository includes a Render Blueprint file. In Render, create a new Blueprint deployment and select this repository. Set a strong `SECRET_KEY` environment variable in the service settings.

**Storage note:** SQLite databases and uploaded files are stored on the service filesystem. On hosting plans without a persistent disk, these files may be lost when the service restarts or redeploys. Configure persistent storage before relying on this app for important documents.

## Security notes

- Passwords are stored as password hashes, not plain text.
- Document downloads check ownership or sharing permissions.
- Audit history is limited to the signed-in user's own events.
- Set a strong, private `SECRET_KEY` in deployment settings.
- This is a learning/hackathon project, not a fully security-audited document vault. Add CSRF protection, malware scanning, rate limiting, backups, and persistent storage before handling sensitive real-world documents.
