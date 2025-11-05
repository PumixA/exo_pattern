from flask import Flask, render_template, redirect, url_for, request, session
from datetime import timedelta
import os
from jinja2 import ChoiceLoader, FileSystemLoader

from security.authentication import AuthenticationEnforcer

# === Gestion robuste des chemins ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))      # /.../exo_pattern/security_app
PROJECT_ROOT = os.path.dirname(BASE_DIR)                   # /.../exo_pattern

TEMPLATE_DIR_1 = os.path.join(BASE_DIR, "templates")       # security_app/templates
TEMPLATE_DIR_2 = os.path.join(PROJECT_ROOT, "templates")   # ../templates

app = Flask(__name__, template_folder=TEMPLATE_DIR_1)
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(TEMPLATE_DIR_1),
    FileSystemLoader(TEMPLATE_DIR_2),
])

app.secret_key = "change-me-in-.env"
app.permanent_session_lifetime = timedelta(minutes=30)

# === Authentification ===
auth = AuthenticationEnforcer(session)

users_db = {
    "admin": auth.hash_password("admin123!"),
    "user": auth.hash_password("user123!")
}

# === Routes ===
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if auth.login_user(username, password, users_db):
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Identifiants incorrects.")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not auth.is_authenticated():
        return redirect(url_for("login"))
    user = session.get("user")
    return render_template("dashboard.html", user=user)

@app.route("/logout")
def logout():
    auth.logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    print("[DEBUG] Template paths:")
    print(" -", TEMPLATE_DIR_1, "exists:", os.path.isdir(TEMPLATE_DIR_1))
    print(" -", TEMPLATE_DIR_2, "exists:", os.path.isdir(TEMPLATE_DIR_2))
    app.run(debug=True)
