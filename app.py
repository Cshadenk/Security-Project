from urllib import response

from flask import Flask, redirect, render_template, request, session
from database import get_db, init_db

app = Flask(__name__) 

app.secret_key = "temporary-key-change-later"

SECURE_MODE = True


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
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        try:
            if not SECURE_MODE:
                query = ("INSERT INTO users (username, password, role)"
                         f"VALUES ('{username}', '{password}', 'user')"
                )
                conn.execute(query)
            else:
             conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
            (username, password)
        )
            conn.commit()
        except Exception:
         conn.close()
         return render_template("register.html", error="Registration failed")
        conn.close()

        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        if not SECURE_MODE:
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            user = conn.execute(query).fetchone()
        else:
            user = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, password)
            ).fetchone()
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


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)