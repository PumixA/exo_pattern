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

---

# 1. Contexte & objectifs

**Contexte :** projet pédagogique pour appliquer des design patterns et bonnes pratiques de sécurité applicative dans une application Flask simple.

**Objectifs pédagogiques :**

* Authentification sécurisée (hachage, sessions, expiration, verrouillage après échecs).
* Autorisation via RBAC et décorateur `@require_permission`.
* Validation et assainissement des entrées (email, username, password, âge).
* Journalisation d’audit (login attempts, anomalies, accès refusés, changements de permission).
* Tests fonctionnels et sécurité : SQLi, XSS, brute-force, escalade de privilèges, expiry/session.

---

# 2. Prérequis

* Python 3.10+ (testé sur 3.13)
* git
* OS : Linux / macOS / WSL / Windows PowerShell
* Ports : accès local 127.0.0.1:5000

Dépendances Python : `flask`, `werkzeug` (install via pip)

---

# 3. Arborescence 

```
exo_pattern/
├── README.md
├── requirements.txt
├── security_app/
│   ├── app.py                  # point d'entrée
│   ├── templates/
│   │   ├── login.html
│   │   └── dashboard.html
│   └── security/
│       ├── authentication.py
│       ├── authorization.py
│       ├── validation.py
│       └── audit.py
└── templates/
         |── dashboard.html
│        └── login.html                # alternative global (loader multi-path)
```

---

# 4. Composants (technique, résumé)

## authentication.py — AuthenticationEnforcer

* `hash_password`, `verify_password` (Werkzeug)
* `login_user(username, password, users_db)` → gère lockout/failed attempts, crée session (`session["user"]`, `session["login_time"]`)
* `is_authenticated()` → vérifie expiration (30 min) et **refresh** `login_time` à chaque activité
* Lockout : 5 échecs → blocage pendant `lockout_time` (10 minutes par défaut)
* Logs : `Login success`, `Login failed`, `Session expired`

## authorization.py

* Map roles → permissions : `admin`, `editor`, `viewer`
* `get_user_role(username)` (démo simple)
* `require_permission(action)` : décorateur Flask protégeant routes HTML
* Optionnel : décorateur API qui renvoie JSON (401/403) pour endpoints JSON

## validation.py — InputValidator

* `validate_username(username)` (3–20 alphanum)
* `validate_password(password)` (>=8, min/maj/chiffre/symbole)
* `validate_email(email)` (regex)
* `validate_age(age)` (13–120)
* `detect_sql_injection(text)` : heuristique ciblée
* `sanitize_html(text)` : échapper HTML

## audit.py — SecurityAuditLogger

* Logs JSON-lines : événements structurés (timestamp, event_type, user, ip, details)
* Principaux événements : `LOGIN_ATTEMPT`, `ANOMALY`, `ACCESS_DENIED`, `PERMISSION_CHANGE`

---

# 5. Endpoints — spécification

## Pages HTML

* `GET /login` → formulaire login (HTML)
* `POST /login` → traitement (form-urlencoded)

  * 302 → `/dashboard` (succès)
  * 400 → input suspect / format invalide
  * 401 → identifiants invalides / compte bloqué
  * Audit : `login_attempt`, `anomaly` si SQLi détecté
* `GET /dashboard` → protégé (session)
* `GET /logout` → clear session

## Admin

* `GET /admin` → `@require_permission("admin")` → 403 si non autorisé; audit ACCESS_DENIED

## API JSON

* `POST /api/users` → création utilisateur (JSON), protégé (`admin`)

  * Input attendu: `{ username, email, password, age }`
  * Vérifications : JSON obligatoire; `username` SQLi check ciblé; validations (username, email, password, age)
  * Réponses: `201`, `400`, `401`, `403`, `409`
  * Audit : `create_user` (ou fallback `anomaly`)

---

# 6. Format des logs d’audit (exemples)

```json
{"timestamp":"2025-11-05T20:53:07Z","event_type":"ANOMALY","user":"admin' OR 1=1--","severity":"WARNING","ip":"127.0.0.1","path":"/login","details":{"kind":"sqli_probe"}}
{"timestamp":"2025-11-05T20:56:22Z","event_type":"LOGIN_ATTEMPT","user":"user","severity":"INFO","ip":"127.0.0.1","details":{"success":true,"locked":false}}
{"timestamp":"2025-11-05T20:57:27Z","event_type":"ACCESS_DENIED","user":"user","severity":"WARNING","ip":"127.0.0.1","path":"/admin","details":{"reason":"forbidden"}}
```

---

# 7. Tests — commandes prêtes

> Lancer le serveur et conserver `run.log` :

```bash
python security_app/app.py > run.log 2>&1 &
tail -f run.log
```

## 1) SQLi — formulaire `/login`

```bash
curl -i -X POST http://127.0.0.1:5000/login \
  -d "username=admin' OR 1=1--" -d "password=whatever"
# Attendu: 400 + message "Entrée suspecte détectée." + audit ANOMALY sqli_probe
```

## 2) Création utilisateur (/api/users) — en admin

```bash
# login admin -> récupérer cookie
curl -c admin.cookies -X POST http://127.0.0.1:5000/login \
  -d "username=admin" -d "password=adminSys123!"

# appel API
curl -b admin.cookies -i -X POST http://127.0.0.1:5000/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"viewer1","email":"v1@example.com","password":"Viewer123!","age":20}'
# Attendu: 201 + {"ok": true, "username": "viewer1"} + audit create_user
```

## 3) Brute-force / lockout (mdp valides en format)

```bash
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:5000/login \\
    -d "username=admin" -d "password=BadPass${i}!"
done
# Attendu : plusieurs 401, puis verrouillage + log
```

## 4) Privilege escalation (/admin)

```bash
curl -c user.cookies -X POST http://127.0.0.1:5000/login -d "username=user" -d "password=uSersyst123!"
curl -b user.cookies -i http://127.0.0.1:5000/admin
# Attendu : 403 + audit ACCESS_DENIED
```

## 5) XSS (si champ libre accepté)

```bash
curl -b admin.cookies -i -X POST http://127.0.0.1:5000/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"xss_test","email":"x@e.com","password":"Xss12345!","age":20,"bio":"<script>alert(1)</script>"}'
# Attendu : rejet ou stockage échappé
```

## 6) Session expiry

* En dev : réduire `session_timeout` à 0.01 min et tester expiration (login, attendre, appeler /dashboard)

---

# 8. Artefacts à rendre

1. `run.log` ou `audit.log` (JSON lines) contenant les événements.
2. `test_report.md` (rapport de tests) : commandes + résultats + extraits de logs/captures.
3. Captures d’écran : SQLi, brute-force, 403 admin, création user 201.
4. Scripts utiles : `bruteforce_test.sh`, `run_tests.sh` (optionnel).

---

# 9. Exemple minimal de test (template)

```markdown
# Rapport de tests - Exercice 6

## 1) SQLi login
- Commande: curl -i -X POST http://127.0.0.1:5000/login -d "username=admin' OR 1=1--" -d "password=whatever"
- Résultat: 400 Entrée suspecte détectée
- Log: artifacts/run.log (ANOMALY sqli_probe)

## 2) Brute-force
- Script: bruteforce_test.sh
- Résultat: compte verrouillé après 5 tentatives (logs: artifacts/login_failures.txt)

## 3) Privilege escalation (/admin)
- Résultat: 403 pour user (audit ACCESS_DENIED)

## 4) Création d'utilisateur via API
- Résultat: 201 ; audit create_user présent
```

---

# 10. Critères d’évaluation (proposition)

* Implémentation fonctionnelle — 40 pts
* Sécurité (hashing, lockout, validations, RBAC, audit) — 30 pts
* Qualité du code & documentation — 20 pts
* Tests & preuves — 10 pts

---

# 11. Recommandations (pour production)

* Ne pas committer `app.secret_key` ; utiliser variables d’environnement.
* Forcer HTTPS + cookies `Secure`, `HttpOnly`, `SameSite=strict`.
* Mettre derrière WSGI (gunicorn) + reverse-proxy (nginx).
* Stockage persistant (DB) pour users et audits ; rotation des logs, monitoring.
* Rate-limiting (IP/app) — `flask-limiter`.
* Tests avancés : OWASP ZAP / fuzzing / CI pipeline.

---

# 12. Checklist avant rendu

* [ ] Code final poussé sur GitHub
* [ ] `artifacts/run.log` et `test_report.md` ajoutés
* [ ] Captures d’écran dans `artifacts/`
* [ ] README et instructions d'installation à jour

---

