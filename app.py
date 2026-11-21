from urllib import response

from flask import Flask, redirect, render_template, request, session
from functools import wraps
from flask import abort
from database import get_db, init_db
from passwords import PASSWORD_RULES, bcrypt_check, bcrypt_hash, md5_hash, validate_password

app = Flask(__name__) 

app.secret_key = "temporary-key-change-later"

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
                # VULNERABLE: MD5 password hash (Wajd), SQL injection (Shaden)
                pw_hash = md5_hash(password)
                query = ("INSERT INTO users (username, password, role)"
                         f"VALUES ('{username}', '{pw_hash}', 'user')"
                )
                conn.execute(query)
            else:
                # SECURE (Wajd): enforce the password policy, then store a bcrypt hash
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
            # VULNERABLE: SQL injection (Shaden) and MD5 comparison (Wajd)
            query = (f"SELECT * FROM users WHERE username='{username}' "
                     f"AND password='{md5_hash(password)}'")
            user = conn.execute(query).fetchone()
        else:
            # SECURE (Wajd): find the user with a parameterized query, then verify the bcrypt hash
            row = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            ).fetchone()
            user = row if (row and bcrypt_check(password, row["password"])) else None
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect("/dashboard")
        
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html")



if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
