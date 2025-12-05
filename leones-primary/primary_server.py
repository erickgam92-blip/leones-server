from flask import Flask, request, redirect, render_template, session, url_for, jsonify
import json
import requests
import os
from datetime import datetime, timedelta

from db_utils import get_connection, init_db
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "cambia-esta-clave"

DB_PATH = os.path.join("db", "primary.db")

# Carpeta para subir imágenes de posts
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Carpeta para avatares
AVATAR_FOLDER = os.path.join("static", "avatars")
os.makedirs(AVATAR_FOLDER, exist_ok=True)

# URLs de las réplicas
REPLICAS = [
    "http://localhost:5001",
    "http://localhost:5002",
]

# IPs que pueden usar funciones de admin (además de ser admin en la BD)
ADMIN_IPS = {
    "10.60.1.229",  # tu WiFi actual (puedes agregar más)
    "127.0.0.1"     # localhost
}

conn = get_connection(DB_PATH)
init_db(conn)


def current_user():
    if "user_id" not in session:
        return None
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    row = cur.fetchone()
    return dict(row) if row else None


def is_admin_allowed():
    user = current_user()
    if not user or user["role"] != "admin":
        return False
    client_ip = request.remote_addr
    return client_ip in ADMIN_IPS


def is_restricted(user):
    """True si el usuario está restringido (no puede publicar / reaccionar / comentar)."""
    if not user:
        return False
    ru = user.get("restricted_until")
    if not ru:
        return False
    try:
        until = datetime.fromisoformat(ru)
    except Exception:
        return False
    return datetime.utcnow() < until


def log_event(event_type, payload_dict):
    cur = conn.cursor()
    payload_json = json.dumps(payload_dict)
    cur.execute(
        "INSERT INTO events_log (event_type, payload) VALUES (?, ?)",
        (event_type, payload_json)
    )
    conn.commit()
    event_id = cur.lastrowid
    return event_id, payload_json


def replicate_event(event_id, event_type, payload_json):
    body = {
        "event_id": event_id,
        "event_type": event_type,
        "payload": json.loads(payload_json),
    }
    for replica in REPLICAS:
        try:
            url = f"{replica}/replicate"
            requests.post(url, json=body, timeout=1)
        except Exception:
            pass


@app.route("/")
def index():
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.content, p.image_filename, p.created_at, u.username
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    """)
    posts = [dict(row) for row in cur.fetchall()]

    for p in posts:
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (p["id"],)
        )
        reactions = {r["reaction_type"]: r["c"] for r in cur.fetchall()}
        p["reactions_by_type"] = reactions

        cur.execute(
            "SELECT c.id, c.content, c.created_at, c.parent_comment_id, u.username "
            "FROM comments c "
            "JOIN users u ON c.user_id = u.id "
            "WHERE c.post_id = ? "
            "ORDER BY c.created_at ASC",
            (p["id"],)
        )
        p["comments"] = [dict(row) for row in cur.fetchall()]

    user = current_user()
    return render_template(
        "index.html",
        posts=posts,
        user=user,
        admin_allowed=is_admin_allowed(),
        restricted=is_restricted(user)
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if not username or not password:
            return render_template("register.html", error="Completa todos los campos.")
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            conn.commit()
            return redirect(url_for("login"))
        except Exception:
            return render_template("register.html", error="Usuario ya existe.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        return render_template("login.html", error="Datos incorrectos.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/posts", methods=["POST"])
def create_post():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if is_restricted(user):
        return "Estás restringido, no puedes publicar por ahora.", 403

    title = request.form["title"].strip()
    content = request.form["content"].strip()
    if not title or not content:
        return redirect(url_for("profile", username=user["username"]))

    image_file = request.files.get("image")
    image_filename = None
    if image_file and image_file.filename:
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        image_file.save(image_path)
        image_filename = filename

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO posts (user_id, title, content, image_filename) VALUES (?, ?, ?, ?)",
        (user["id"], title, content, image_filename)
    )
    conn.commit()
    post_id = cur.lastrowid

    event_id, payload_json = log_event("CREATE_POST", {
        "post_id": post_id,
        "user_id": user["id"],
        "title": title,
        "content": content,
        "image_filename": image_filename,
    })
    replicate_event(event_id, "CREATE_POST", payload_json)

    return redirect(url_for("profile", username=user["username"]))


@app.route("/posts/<int:post_id>/react", methods=["POST"])
def react_post(post_id):
    user = current_user()
    if not user:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "login required"}), 401
        return redirect(url_for("login"))

    if is_restricted(user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "restricted", "until": user.get("restricted_until")}), 403
        return "Estás restringido, no puedes reaccionar.", 403

    reaction_type = request.form.get("reaction_type", "like").strip() or "like"

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO reactions (user_id, post_id, reaction_type)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, post_id) DO UPDATE SET reaction_type = excluded.reaction_type
        """,
        (user["id"], post_id, reaction_type)
    )
    conn.commit()

    event_id, payload_json = log_event("REACT_POST", {
        "post_id": post_id,
        "user_id": user["id"],
        "reaction_type": reaction_type,
    })
    replicate_event(event_id, "REACT_POST", payload_json)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (post_id,)
        )
        reactions = {r["reaction_type"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (post_id,))
        comments_count = cur.fetchone()[0]
        return jsonify({
            "ok": True,
            "post_id": post_id,
            "reactions": reactions,
            "comments_count": comments_count
        })

    return redirect(url_for("index"))


@app.route("/posts/<int:post_id>/comment", methods=["POST"])
def comment_post(post_id):
    user = current_user()
    if not user:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "login required"}), 401
        return redirect(url_for("login"))

    if is_restricted(user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "restricted", "until": user.get("restricted_until")}), 403
        return "Estás restringido, no puedes comentar.", 403

    content = request.form["content"].strip()
    parent_comment_id_raw = request.form.get("parent_comment_id", "").strip()
    parent_comment_id = int(parent_comment_id_raw) if parent_comment_id_raw else None

    if not content:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "empty"}), 400
        return redirect(url_for("index"))

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO comments (user_id, post_id, content, parent_comment_id) VALUES (?, ?, ?, ?)",
        (user["id"], post_id, content, parent_comment_id)
    )
    conn.commit()
    comment_id = cur.lastrowid

    event_id, payload_json = log_event("COMMENT_POST", {
        "comment_id": comment_id,
        "post_id": post_id,
        "user_id": user["id"],
        "content": content,
        "parent_comment_id": parent_comment_id,
    })
    replicate_event(event_id, "COMMENT_POST", payload_json)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cur.execute(
            "SELECT c.content, c.created_at, c.parent_comment_id, u.username "
            "FROM comments c JOIN users u ON c.user_id = u.id "
            "WHERE c.id = ?",
            (comment_id,)
        )
        row = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (post_id,))
        comments_count = cur.fetchone()[0]
        return jsonify({
            "ok": True,
            "post_id": post_id,
            "comment": {
                "id": comment_id,
                "username": row["username"],
                "content": row["content"],
                "created_at": row["created_at"],
                "parent_comment_id": row["parent_comment_id"]
            },
            "comments_count": comments_count
        })

    return redirect(url_for("index"))


@app.route("/admin/posts/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    """Eliminar post como admin (desde cualquier perfil / timeline)."""
    if not is_admin_allowed():
        return "No autorizado (fuera de la red permitida o no eres admin)", 403

    cur = conn.cursor()
    cur.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    cur.execute("DELETE FROM reactions WHERE post_id = ?", (post_id,))
    cur.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
    conn.commit()

    event_id, payload_json = log_event("DELETE_POST", {"post_id": post_id})
    replicate_event(event_id, "DELETE_POST", payload_json)
    return redirect(url_for("index"))


# 🔹 NUEVO: eliminar post propio desde el perfil
@app.route("/user/posts/<int:post_id>/delete", methods=["POST"])
def delete_own_post(post_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    cur = conn.cursor()
    cur.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        return "Post no encontrado", 404
    if row["user_id"] != user["id"]:
        return "No autorizado", 403

    cur.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    cur.execute("DELETE FROM reactions WHERE post_id = ?", (post_id,))
    cur.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
    conn.commit()

    event_id, payload_json = log_event("DELETE_POST", {"post_id": post_id})
    replicate_event(event_id, "DELETE_POST", payload_json)
    return redirect(url_for("profile", username=user["username"]))


# 🔹 NUEVO: editar post propio
@app.route("/user/posts/<int:post_id>/edit", methods=["GET", "POST"])
def edit_own_post(post_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    cur = conn.cursor()
    cur.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        return "Post no encontrado", 404
    post = dict(row)
    if post["user_id"] != user["id"]:
        return "No autorizado", 403

    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()
        if not title or not content:
            return render_template("edit_post.html", post=post, error="Título y contenido son obligatorios.", user=user)

        image_filename = post["image_filename"]
        image_file = request.files.get("image")
        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            image_file.save(image_path)
            image_filename = filename

        cur.execute(
            "UPDATE posts SET title = ?, content = ?, image_filename = ? WHERE id = ?",
            (title, content, image_filename, post_id)
        )
        conn.commit()

        event_id, payload_json = log_event("UPDATE_POST", {
            "post_id": post_id,
            "title": title,
            "content": content,
            "image_filename": image_filename,
        })
        replicate_event(event_id, "UPDATE_POST", payload_json)

        return redirect(url_for("profile", username=user["username"]))

    return render_template("edit_post.html", post=post, user=user, admin_allowed=is_admin_allowed())


@app.route("/profile/<username>")
def profile(username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        return "Usuario no encontrado", 404
    profile_user = dict(user_row)

    cur.execute("""
        SELECT p.id, p.title, p.content, p.image_filename, p.created_at,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comments_count
        FROM posts p
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    """, (profile_user["id"],))
    posts = [dict(row) for row in cur.fetchall()]

    user = current_user()
    return render_template(
        "profile.html",
        profile_user=profile_user,
        posts=posts,
        user=user,
        admin_allowed=is_admin_allowed(),
        restricted=is_restricted(user)
    )


@app.route("/profile/upload_avatar", methods=["POST"])
def upload_avatar():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    file = request.files.get("avatar")
    if file and file.filename:
        filename = secure_filename(f"user{user['id']}_{file.filename}")
        path = os.path.join(AVATAR_FOLDER, filename)
        file.save(path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET profile_image = ? WHERE id = ?",
            (filename, user["id"])
        )
        conn.commit()
    return redirect(url_for("profile", username=user["username"]))


@app.route("/admin/users/<int:user_id>/restrict", methods=["POST"])
def restrict_user(user_id):
    if not is_admin_allowed():
        return "No autorizado", 403

    minutes_str = request.form.get("minutes", "0").strip()
    try:
        minutes = int(minutes_str)
    except ValueError:
        minutes = 0

    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return "Usuario no encontrado", 404
    username = row["username"]

    if minutes <= 0:
        cur.execute("UPDATE users SET restricted_until = NULL WHERE id = ?", (user_id,))
    else:
        until = datetime.utcnow() + timedelta(minutes=minutes)
        cur.execute("UPDATE users SET restricted_until = ? WHERE id = ?", (until.isoformat(), user_id))
    conn.commit()

    return redirect(url_for("profile", username=username))


@app.route("/sync")
def sync_events():
    last_id = int(request.args.get("last_event_id", 0))
    cur = conn.cursor()
    cur.execute(
        "SELECT id, event_type, payload FROM events_log WHERE id > ? ORDER BY id ASC",
        (last_id,)
    )
    rows = cur.fetchall()
    events = []
    for r in rows:
        events.append({
            "id": r["id"],
            "event_type": r["event_type"],
            "payload": json.loads(r["payload"]),
        })
    return jsonify(events)


@app.route("/api/reactions_summary")
def reactions_summary():
    cur = conn.cursor()
    cur.execute("SELECT id FROM posts")
    post_ids = [row["id"] for row in cur.fetchall()]

    result = []
    for pid in post_ids:
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (pid,)
        )
        reactions = {r["reaction_type"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (pid,))
        comments_count = cur.fetchone()[0]
        result.append({
            "post_id": pid,
            "reactions": reactions,
            "comments_count": comments_count
        })
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
