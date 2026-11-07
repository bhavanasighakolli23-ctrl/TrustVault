import os
import sqlite3
import secrets
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory,
    abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from database import init_db, get_db, close_db

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {"pdf", "txt", "doc", "docx", "png", "jpg", "jpeg"}

app.teardown_appcontext(close_db)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def log_action(user_id, action, document_id=None, details=""):
    db = get_db()
    db.execute(
        """INSERT INTO audit_logs
           (user_id, document_id, action, details, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (
            user_id,
            document_id,
            action,
            details,
            datetime.now().isoformat(timespec="seconds")
        )
    )
    db.commit()


def is_document_owner(user_id, document_id):
    """Return True only for the document's owner."""
    document = get_db().execute(
        "SELECT owner_id FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()
    return bool(document and document["owner_id"] == user_id)


def can_access_document(user_id, document_id, required="read"):
    db = get_db()
    document = db.execute(
        "SELECT * FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()

    if not document:
        return False
    if document["owner_id"] == user_id:
        return True

    permission = db.execute(
        """SELECT permission FROM permissions
           WHERE document_id = ? AND user_id = ?""",
        (document_id, user_id)
    ).fetchone()

    if not permission:
        return False
    if required == "edit":
        return permission["permission"] == "edit"
    return permission["permission"] in ("read", "edit")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(password) < 8:
            flash("Username must be 3+ characters and password 8+ characters.")
            return redirect(url_for("register"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), "user")
            )
            db.commit()
            flash("Account created. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            return redirect(url_for("register"))

    return render_template("login.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_action(user["id"], "login")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html", mode="login")


@app.route("/logout")
@login_required
def logout():
    user_id = session["user_id"]
    log_action(user_id, "logout")
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_id = session["user_id"]
    documents = db.execute(
        """SELECT DISTINCT d.* FROM documents d
           LEFT JOIN permissions p ON d.id = p.document_id
           WHERE d.owner_id = ? OR p.user_id = ?
           ORDER BY d.created_at DESC""",
        (user_id, user_id)
    ).fetchall()
    users = db.execute(
        "SELECT id, username FROM users WHERE id != ?",
        (user_id,)
    ).fetchall()
    return render_template("dashboard.html", documents=documents, users=users)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a file to upload.")
        return redirect(url_for("dashboard"))
    if not allowed_file(file.filename):
        flash("File type not allowed.")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(file.filename)
    stored_name = secrets.token_hex(16) + "_" + original_name
    file.save(os.path.join(UPLOAD_FOLDER, stored_name))

    db = get_db()
    cursor = db.execute(
        """INSERT INTO documents
           (owner_id, original_name, stored_name, created_at)
           VALUES (?, ?, ?, ?)""",
        (
            session["user_id"], original_name, stored_name,
            datetime.now().isoformat(timespec="seconds")
        )
    )
    db.commit()
    log_action(session["user_id"], "upload", cursor.lastrowid, original_name)
    flash("Document uploaded.")
    return redirect(url_for("dashboard"))


@app.route("/download/<int:document_id>")
@login_required
def download(document_id):
    if not can_access_document(session["user_id"], document_id):
        log_action(session["user_id"], "denied_download", document_id)
        abort(403)

    db = get_db()
    document = db.execute(
        "SELECT * FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    log_action(session["user_id"], "download", document_id)
    return send_from_directory(
        UPLOAD_FOLDER, document["stored_name"],
        as_attachment=True, download_name=document["original_name"]
    )


@app.route("/share/<int:document_id>", methods=["POST"])
@login_required
def share(document_id):
    user_id = session["user_id"]
    if not is_document_owner(user_id, document_id):
        abort(403)

    target_id = request.form.get("user_id", type=int)
    permission = request.form.get("permission", "read")
    if permission not in ("read", "edit") or target_id == user_id:
        abort(400)

    db = get_db()
    target = db.execute(
        "SELECT id FROM users WHERE id = ?", (target_id,)
    ).fetchone()
    if not target:
        flash("User not found.")
        return redirect(url_for("dashboard"))

    db.execute(
        """INSERT INTO permissions (document_id, user_id, permission)
           VALUES (?, ?, ?)
           ON CONFLICT(document_id, user_id)
           DO UPDATE SET permission = excluded.permission""",
        (document_id, target_id, permission)
    )
    db.commit()
    log_action(user_id, "share", document_id,
               f"Shared with user {target_id}: {permission}")
    flash("Permission updated.")
    return redirect(url_for("dashboard"))


@app.route("/revoke/<int:document_id>/<int:target_id>", methods=["POST"])
@login_required
def revoke(document_id, target_id):
    user_id = session["user_id"]
    if not is_document_owner(user_id, document_id):
        abort(403)

    db = get_db()
    db.execute(
        "DELETE FROM permissions WHERE document_id = ? AND user_id = ?",
        (document_id, target_id)
    )
    db.commit()
    log_action(user_id, "revoke", document_id,
               f"Revoked access from user {target_id}")
    flash("Access revoked.")
    return redirect(url_for("dashboard"))


@app.route("/audit")
@login_required
def audit():
    db = get_db()
    logs = db.execute(
        """SELECT a.*, u.username FROM audit_logs a
           LEFT JOIN users u ON a.user_id = u.id
           WHERE a.user_id = ?
           ORDER BY a.id DESC LIMIT 200""",
        (session["user_id"],)
    ).fetchall()
    return render_template("audit.html", logs=logs)


@app.errorhandler(403)
def forbidden(error):
    return "Access denied.", 403


@app.errorhandler(413)
def too_large(error):
    return "File too large. Maximum size is 10 MB.", 413


init_db()

if __name__ == "__main__":
    app.run(debug=True)
