from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import logging


class AuthenticationEnforcer:
    def __init__(self, session_store, session_timeout=30):
        """
        session_store : objet de session Flask (dictionnaire)
        session_timeout : durée en minutes avant expiration
        """
        self.session_store = session_store
        self.session_timeout = timedelta(minutes=session_timeout)

        # Configuration du logger
        self.logger = logging.getLogger("auth_logger")
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )

    def hash_password(self, password: str) -> str:
        """Retourne le hash sécurisé d’un mot de passe"""
        return generate_password_hash(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        """Vérifie qu’un mot de passe correspond à son hash"""
        return check_password_hash(hashed, password)

    def login_user(self, username: str, password: str, users_db: dict):
        """
        users_db : dictionnaire {username: hashed_password}
        """
        user_hash = users_db.get(username)
        if user_hash and self.verify_password(password, user_hash):
            # Connexion réussie
            self.session_store["user"] = username
            self.session_store["login_time"] = datetime.utcnow().isoformat()
            self.logger.info(f"Login success for {username}")
            return True
        else:
            # Échec de connexion
            self.logger.warning(f"Login failed for {username}")
            return False

    def is_authenticated(self) -> bool:
        """Vérifie si la session utilisateur est encore valide"""
        if "login_time" not in self.session_store:
            return False

        login_time = datetime.fromisoformat(self.session_store["login_time"])
        if datetime.utcnow() - login_time > self.session_timeout:
            self.logger.info("Session expired")
            self.session_store.clear()
            return False

        return True

    def logout_user(self):
        """Déconnecte proprement l’utilisateur"""
        user = self.session_store.get("user", "Unknown")
        self.logger.info(f"Logout for {user}")
        self.session_store.clear()
