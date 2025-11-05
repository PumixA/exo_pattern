from flask import Flask, render_template, redirect, url_for, request, session
from datetime import timedelta
import os
from jinja2 import ChoiceLoader, FileSystemLoader

from security.authentication import AuthenticationEnforcer
from security.authorization import AuthorizationEnforcer, require_permission
from security.validation import InputValidator
from security.audit import SecurityAuditLogger

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
audit = SecurityAuditLogger() 

users_db = {
    "admin": auth.hash_password("adminSys123!"),
    "user": auth.hash_password("uSersyst123!")
}

def _client_ip():
    # Simple IP extraction; à adapter derrière un proxy (X-Forwarded-For)
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")

# === Routes ===
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = _client_ip()
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # 1) Détection SQLi basique
        if validator.detect_sql_injection(username) or validator.detect_sql_injection(password):
            audit.anomaly(user=username or None, ip=ip, kind="sqli_probe", data={"path": request.path})
            return render_template("login.html", error="Entrée suspecte détectée.", last_username=username), 400

        # 2) Validation format username/password
        if not validator.validate_username(username):
            return render_template("login.html", error="Nom d'utilisateur invalide (3–20 alphanum).", last_username=username), 400

        if not validator.validate_password(password):
            return render_template("login.html", error="Mot de passe invalide (8+ avec min/maj/chiffre/symbole).", last_username=username), 400

        # 3) Authentification
        locked = False
        # (On check l'état de lock si dispo)
        try:
            locked = getattr(auth, "_is_locked")(username)  # pour l'audit (exercice)
        except Exception:
            pass

        success = auth.login_user(username, password, users_db)
        audit.login_attempt(user=username, ip=ip, success=success, locked=locked)

        if success:
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Identifiants incorrects ou compte bloqué.", last_username=username), 401

    # GET
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

# === Gestion centralisée des erreurs ===
@app.errorhandler(403)
def handle_403(e):
    user = session.get("user")
    ip = _client_ip()
    audit.access_denied(user=user, ip=ip, path=request.path, reason="forbidden")
    return "403 Forbidden", 403

@app.errorhandler(500)
def handle_500(e):
    user = session.get("user")
    ip = _client_ip()
    audit.anomaly(user=user, ip=ip, kind="server_error", data={"path": request.path})
    return "500 Internal Server Error", 500