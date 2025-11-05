from flask import Flask, render_template, redirect, url_for, request, session
from datetime import timedelta
import os
from jinja2 import ChoiceLoader, FileSystemLoader

from security.authentication import AuthenticationEnforcer
from security.authorization import AuthorizationEnforcer, require_permission
from security.validation import InputValidator

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
validator = InputValidator()

users_db = {
    "admin": auth.hash_password("adminSys123!"),
    "user": auth.hash_password("uSersyst123!")
}

# === Routes ===
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # 1) Détection SQLi basique
        if validator.detect_sql_injection(username) or validator.detect_sql_injection(password):
            return render_template("login.html", error="Entrée suspecte détectée.", last_username=username), 400

        # 2) Validation format username/password
        if not validator.validate_username(username):
            return render_template("login.html", error="Nom d'utilisateur invalide (3–20 alphanum).", last_username=username), 400

        # On valide aussi le format du mot de passe (coté client + serveur)
        if not validator.validate_password(password):
            return render_template("login.html", error="Mot de passe invalide (8+ avec min/maj/chiffre/symbole).", last_username=username), 400

        # 3) Authentification
        if auth.login_user(username, password, users_db):
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Identifiants incorrects ou compte bloqué.", last_username=username), 401

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

@app.route("/admin")
@require_permission("admin")
def admin_panel():
    if not auth.is_authenticated():
        return redirect(url_for("login"))
    user = session.get("user")
    return f"<h1>Bienvenue sur la page admin, {user} 👑</h1>"
