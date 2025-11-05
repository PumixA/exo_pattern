from flask import Flask, render_template, redirect, url_for, session
from datetime import timedelta
import os

from jinja2 import ChoiceLoader, FileSystemLoader

# === Résolution robuste des chemins ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # .../exo_pattern/security_app
PROJECT_ROOT = os.path.dirname(BASE_DIR)                       # .../exo_pattern

# Candidats possibles pour le dossier templates
TEMPLATE_DIR_1 = os.path.join(BASE_DIR, "templates")           # security_app/templates
TEMPLATE_DIR_2 = os.path.join(PROJECT_ROOT, "templates")       # ../templates

# On garde TEMPLATE_DIR_1 comme défaut pour Flask
app = Flask(__name__, template_folder=TEMPLATE_DIR_1)

# On ajoute un loader Jinja qui cherche dans les deux dossiers
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(TEMPLATE_DIR_1),
    FileSystemLoader(TEMPLATE_DIR_2),
])

app.secret_key = "change-me-in-.env"  # à sécuriser plus tard
app.permanent_session_lifetime = timedelta(minutes=30)

# === (optionnel) petit debug de démarrage : affiche où on va chercher ===
if __name__ == "__main__":
    print("[DEBUG] Template search paths:")
    print(" -", TEMPLATE_DIR_1, "exists:", os.path.isdir(TEMPLATE_DIR_1))
    print(" -", TEMPLATE_DIR_2, "exists:", os.path.isdir(TEMPLATE_DIR_2))

# === Routes ===
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# === Lancement ===
if __name__ == "__main__":
    app.run(debug=True)
