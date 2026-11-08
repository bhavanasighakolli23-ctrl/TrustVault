import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, abort, flash, redirect, render_template, request,
    send_from_directory, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from database import close_db, get_db, init_db

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads"))
ALLOWED_EXTENSIONS = {"pdf", "txt", "doc", "docx", "png", "jpg", "jpeg"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
)
app.teardown_appcontext(close_db)


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def log_action(user_id, action, document_id=None, details=""):
    db = get_db()
    db.execute(
        """INSERT INTO audit_logs (user_id, document_id, action, details, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, document_id, action, details, timestamp()),
    )
    db.commit()


def is_document_owner(user_id, document_id):
    row = get_db().execute(
        "SELECT owner_id FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    return bool(row and row["owner_id"] == user_id)


def can_access_document(user_id, document_id, required="read"):
    db = get_db()
    document = db.execute(
        "SELECT owner_id FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    if not document:
        return False
    if document["owner_id"] == user_id:
        return True
    row = db.execute(
        "SELECT permission FROM permissions WHERE document_id = ? AND user_id = ?",
        (document_id, user_id),
    ).fetchone()
    if not row:
        return False
    return row["permission"] == "edit" if required == "edit" else row["permission"] in ("read", "edit")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 40 or len(password) < 8:
            flash("Username must be 3–40 characters and password at least 8 characters.")
            return redirect(url_for("register"))
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            return redirect(url_for("register"))
        flash("Account created. Please log in.")
        return redirect(url_for("login"))
    return render_template("login.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_action(user["id"], "login")
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html", mode="login")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user_id = session["user_id"]
    log_action(user_id, "logout")
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    db = get_db()
    documents = db.execute(
        """SELECT DISTINCT d.*, u.username AS owner_name
           FROM documents d
           JOIN users u ON u.id = d.owner_id
           LEFT JOIN permissions p ON p.document_id = d.id
           WHERE d.owner_id = ? OR p.user_id = ?
           ORDER BY d.created_at DESC""",
        (user_id, user_id),
    ).fetchall()
    users = db.execute(
        "SELECT id, username FROM users WHERE id != ? ORDER BY username", (user_id,)
    ).fetchall()
    return render_template("dashboard.html", documents=documents, users=users)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Choose a file to upload.")
        return redirect(url_for("dashboard"))
    if not allowed_file(uploaded.filename):
        flash("File type not allowed.")
        return redirect(url_for("dashboard"))
    original_name = secure_filename(uploaded.filename)
    if not original_name:
        flash("Please choose a valid file name.")
        return redirect(url_for("dashboard"))
    stored_name = secrets.token_hex(16) + "_" + original_name
    uploaded.save(os.path.join(app.config["UPLOAD_FOLDER"], stored_name))
    db = get_db()
    cursor = db.execute(
        """INSERT INTO documents (owner_id, original_name, stored_name, created_at)
           VALUES (?, ?, ?, ?)""",
        (session["user_id"], original_name, stored_name, timestamp()),
    )
    db.commit()
    log_action(session["user_id"], "upload", cursor.lastrowid, original_name)
    flash("Document uploaded.")
    return redirect(url_for("dashboard"))


@app.route("/download/<int:document_id>")
@login_required
def download(document_id):
    user_id = session["user_id"]
    if not can_access_document(user_id, document_id):
        log_action(user_id, "denied_download", document_id)
        abort(403)
    document = get_db().execute(
        "SELECT original_name, stored_name FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    if not document:
        abort(404)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], document["stored_name"])
    if not os.path.isfile(file_path):
        abort(404)
    log_action(user_id, "download", document_id)
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["stored_name"],
        as_attachment=True,
        download_name=document["original_name"],
    )


@app.route("/share/<int:document_id>", methods=["POST"])
@login_required
def share(document_id):
    user_id = session["user_id"]
    if not is_document_owner(user_id, document_id):
        abort(403)
    target_id = request.form.get("user_id", type=int)
    permission = request.form.get("permission", "read")
    if not target_id or target_id == user_id or permission not in ("read", "edit"):
        abort(400)
    db = get_db()
    target = db.execute("SELECT id FROM users WHERE id = ?", (target_id,)).fetchone()
    if not target:
        flash("User not found.")
        return redirect(url_for("dashboard"))
    document = db.execute("SELECT id FROM documents WHERE id = ?", (document_id,)).fetchone()
    if not document:
        abort(404)
    db.execute(
        """INSERT INTO permissions (document_id, user_id, permission)
           VALUES (?, ?, ?)
           ON CONFLICT(document_id, user_id)
           DO UPDATE SET permission = excluded.permission""",
        (document_id, target_id, permission),
    )
    db.commit()
    log_action(user_id, "share", document_id, f"Shared with user {target_id}: {permission}")
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
        (document_id, target_id),
    )
    db.commit()
    log_action(user_id, "revoke", document_id, f"Revoked access from user {target_id}")
    flash("Access revoked.")
    return redirect(url_for("dashboard"))


@app.route("/audit")
@login_required
def audit():
    logs = get_db().execute(
        """SELECT a.*, u.username FROM audit_logs a
           LEFT JOIN users u ON u.id = a.user_id
           WHERE a.user_id = ? ORDER BY a.id DESC LIMIT 200""",
        (session["user_id"],),
    ).fetchall()
    return render_template("audit.html", logs=logs)


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="You do not have permission to access this resource."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="The requested page or document was not found."), 404


@app.errorhandler(413)
def too_large(error):
    return render_template("error.html", code=413, message="File too large. Maximum upload size is 10 MB."), 413


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
