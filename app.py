from flask import Flask, redirect, render_template, request, session
from functools import wraps
from flask import abort
from database import get_db, init_db
from passwords import PASSWORD_RULES, bcrypt_check, bcrypt_hash, md5_hash, validate_password
from xss_utils import sanitize_comment
from crypto_session import SessionCryptoManager

app = Flask(__name__) 
crypto = SessionCryptoManager()
crypto.apply_flask_session_config(app)

# Toggle between the vulnerable version (False) and the mitigated version (True)
# so each attack and its corresponding defense can be demonstrated side by side.
SECURE_MODE = True


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow access without role checks in vulnerable mode.
        if not SECURE_MODE:
            return f(*args, **kwargs)
        # Redirect users who are not logged in.
        if "user_id" not in session:
            return redirect("/login")
# Check the user's current role in the database on each request.
# This ensures revoked admin access is denied immediately.
        conn = get_db()

        user = conn.execute(
            "SELECT role FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        conn.close()

        if user is None or user["role"] != "admin":
            abort(403)

        return f(*args, **kwargs)

    return decorated_function

# Prevent browsers from caching protected pages (e.g., /dashboard) so pressing
# the Back button after logout cannot display a cached copy.
@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    # Password rules are shown to the user in secure mode only
    rules = PASSWORD_RULES if SECURE_MODE else None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        try:
            if not SECURE_MODE:
                pw_hash = md5_hash(password)
                query = ("INSERT INTO users (username, password, role)"
                         f"VALUES ('{username}', '{pw_hash}', 'user')"
                )
                conn.execute(query)
                # SECURE: Use parameterized queries (?) to separate SQL structure from user data
                # (preventing SQL Injection), and hard-code 'user' role to prevent privilege escalation.
            else:
                errors = validate_password(password)
                if errors:
                    conn.close()
                    return render_template("register.html", errors=errors, rules=rules), 400
                conn.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
                    (username, bcrypt_hash(password))
                )
            conn.commit()
        except Exception:
         conn.close()
         return render_template("register.html", error="Registration failed", rules=rules)
        conn.close()

        return redirect("/login")
    return render_template("register.html", rules=rules)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        if not SECURE_MODE:
            query = (f"SELECT * FROM users WHERE username='{username}' "
                     f"AND password='{md5_hash(password)}'")
            user = conn.execute(query).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()
            user = row if (row and bcrypt_check(password, row["password"])) else None
        conn.close()

        # Store standard session keys for route checks alongside Fernet-encrypted copies
        # of sensitive fields (user_id, role) to protect session data.

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["enc_user_id"] = crypto.encrypt_value(str(user["id"]))
            session["enc_role"] = crypto.encrypt_value(str(user["role"]))
            return redirect("/dashboard")
        
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

# Enforce authentication by verifying an active session before rendering the dashboard.
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html")

# Terminate the session completely on logout so direct URLs or Back-button
# navigation cannot restore access.
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    if request.method == "POST":
        text = request.form.get("comment", "")[:500]
        if SECURE_MODE:
            text = sanitize_comment(text)
        conn.execute("INSERT INTO comments (username, text) VALUES (?, ?)",
                     (session["username"], text))
        conn.commit()

    rows = conn.execute("SELECT username, text FROM comments ORDER BY id DESC").fetchall()
    conn.close()

   
    items = [{"username": r["username"],
              "text": sanitize_comment(r["text"]) if SECURE_MODE else r["text"]}
             for r in rows]
    return render_template("comments.html", comments=items)


@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html")


# Run Flask over HTTPS using an auto-generated self-signed TLS certificate
# to encrypt data in transit (port 5001 avoids macOS AirPlay conflict on 5000).
if __name__ == "__main__":
    init_db()
    cert_path, key_path = crypto.ensure_self_signed_cert()
    app.run(debug=True, host="127.0.0.1", port=5001, ssl_context=(cert_path, key_path))
