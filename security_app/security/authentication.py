from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import logging


class AuthenticationEnforcer:
    def __init__(self, session_store, session_timeout=30, lockout_time=10):
        """
        session_store : objet de session Flask (dict)
        session_timeout : durée en minutes avant expiration
        lockout_time : durée en minutes d'un blocage après 5 échecs
        """
        self.session_store = session_store
        self.session_timeout = timedelta(minutes=session_timeout)
        self.lockout_time = timedelta(minutes=lockout_time)
        self.failed_attempts = {}  # {username: {"count": int, "last_fail": datetime}}

        # Configuration du logger
        self.logger = logging.getLogger("auth_logger")
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )

    # === Méthodes principales ===

    def hash_password(self, password: str) -> str:
        return generate_password_hash(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        return check_password_hash(hashed, password)

    def login_user(self, username: str, password: str, users_db: dict) -> bool:
        """Vérifie les identifiants, gère les échecs et la connexion"""

        # Vérifier si l'utilisateur est temporairement bloqué
        if self._is_locked(username):
            self.logger.warning(f"User '{username}' temporarily locked out.")
            return False

        user_hash = users_db.get(username)
        if user_hash and self.verify_password(password, user_hash):
            # Succès de connexion
            self.session_store["user"] = username
            self.session_store["login_time"] = datetime.utcnow().isoformat()
            self.logger.info(f"Login success for {username}")
            self._reset_attempts(username)
            return True
        else:
            # Échec
            self._record_failed_attempt(username)
            self.logger.warning(f"Login failed for {username}")
            return False

    def is_authenticated(self) -> bool:
        """Vérifie si la session est encore valide"""
        if "login_time" not in self.session_store:
            return False

        login_time = datetime.fromisoformat(self.session_store["login_time"])
        if datetime.utcnow() - login_time > self.session_timeout:
            self.logger.info("Session expired")
            self.session_store.clear()
            return False

        # Si valide, on renouvelle la session (activité)
        self._refresh_session()
        return True

    def logout_user(self):
        user = self.session_store.get("user", "Unknown")
        self.logger.info(f"Logout for {user}")
        self.session_store.clear()

    # === Fonctions internes ===

    def _record_failed_attempt(self, username: str):
        now = datetime.utcnow()
        if username not in self.failed_attempts:
            self.failed_attempts[username] = {"count": 1, "last_fail": now}
        else:
            self.failed_attempts[username]["count"] += 1
            self.failed_attempts[username]["last_fail"] = now

    def _reset_attempts(self, username: str):
        if username in self.failed_attempts:
            del self.failed_attempts[username]

    def _is_locked(self, username: str) -> bool:
        """Renvoie True si le compte est bloqué après 5 échecs récents"""
        data = self.failed_attempts.get(username)
        if not data:
            return False
        count = data["count"]
        last_fail = data["last_fail"]
        if count >= 5 and datetime.utcnow() - last_fail < self.lockout_time:
            return True
        if datetime.utcnow() - last_fail > self.lockout_time:
            # Délai écoulé → reset du compteur
            self._reset_attempts(username)
        return False

    def _refresh_session(self):
        """Renouvelle la session à chaque activité"""
        self.session_store["login_time"] = datetime.utcnow().isoformat()
