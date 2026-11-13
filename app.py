from flask import Flask, redirect, render_template, request
from database import get_db, init_db

app = Flask(__name__) 
init_db()
# False = ضعيف (SQL Injection يشتغل)
# True  = آمن (parameterized queries)
SECURE_MODE = True
@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )
        conn.commit()
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
            return f"Welcome {user['username']}!"
        return "Invalid credentials"
    return render_template("login.html")

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)