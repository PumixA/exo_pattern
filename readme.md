# TP – Design Patterns Sécurité (Flask)

## 🚀 Installation et exécution

1. **Cloner le projet**
   ```bash
   git clone git@github.com:PumixA/exo_pattern.git
   cd exo_pattern

2. **Créer et activer l’environnement virtuel**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate    # sous Linux/Mac
   # ou
   .venv\Scripts\Activate.ps1   # sous Windows
   ```

3. **Installer les dépendances**

   ```bash
   pip install --upgrade pip
   pip install flask flask-login werkzeug
   pip freeze > requirements.txt
   ```

4. **Lancer l’application**

   ```bash
   python security_app/app.py
   ```

   > Si tu préfères via Flask CLI :
   >
   > ```bash
   > export FLASK_APP=security_app.app
   > flask run --debug
   > ```

5. **Ouvrir dans ton navigateur**

    * [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login)
    * [http://127.0.0.1:5000/dashboard](http://127.0.0.1:5000/dashboard)

6. **Problèmes courants**

    * Si `TemplateNotFound`, vérifie que les fichiers sont bien dans
      `security_app/templates/` (login.html et dashboard.html)
    * Si `ModuleNotFoundError: No module named 'flask'`, réactive ton environnement :

      ```bash
      source .venv/bin/activate
      ```

C’est tout. Après ces étapes, l’application Flask est opérationnelle. 🎉