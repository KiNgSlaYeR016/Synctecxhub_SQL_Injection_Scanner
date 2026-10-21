# Deliberately vulnerable Flask app - built ONLY as a safe, legal local target
# to test the SQL injection scanner against. Do not deploy this anywhere real -
# it's intentionally broken.

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
DB_FILE = "test_users.db"


def init_db():
    # sets up a tiny fake users table so there's something to actually query
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecret123')")
    cur.execute("INSERT INTO users (username, password) VALUES ('testuser', 'password1')")
    conn.commit()
    conn.close()


LOGIN_PAGE = """
<h2>Test Login (Intentionally Vulnerable)</h2>
<form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <input type="submit" value="Login">
</form>
{% if result %}<p>{{ result }}</p>{% endif %}
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE ON PURPOSE: raw string concatenation instead of parameterized query.
        # This is exactly the kind of mistake the scanner is designed to detect.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
            if row:
                result = f"Login successful. Welcome, {row[1]}."
            else:
                result = "Invalid username or password."
        except sqlite3.OperationalError as e:
            # deliberately leaking the raw DB error - a classic real-world SQLi indicator
            result = f"Database error: {e}"
        conn.close()

    return render_template_string(LOGIN_PAGE, result=result)


@app.route("/")
def home():
    return '<p>Vulnerable test app running. Go to <a href="/login">/login</a></p>'


if __name__ == "__main__":
    init_db()
    print("Vulnerable test app running at http://127.0.0.1:5000/login")
    app.run(debug=True)