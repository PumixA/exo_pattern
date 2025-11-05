from functools import wraps
from flask import session, redirect, url_for, abort
import logging


class AuthorizationEnforcer:
    def __init__(self):
        self.roles = {
            "admin": {"read", "write", "delete", "admin"},
            "editor": {"read", "write"},
            "viewer": {"read"},
        }
        self.logger = logging.getLogger("authz_logger")

    def get_user_role(self, username: str) -> str:
        """
        Retourne le rôle d’un utilisateur (exemple simple basé sur le nom)
        Tu peux plus tard relier ça à une vraie base de données.
        """
        if username == "admin":
            return "admin"
        elif username == "user":
            return "editor"
        else:
            return "viewer"

    def can_access(self, username: str, action: str) -> bool:
        """Vérifie si l’utilisateur a la permission demandée"""
        role = self.get_user_role(username)
        allowed_actions = self.roles.get(role, set())
        return action in allowed_actions


# === Décorateur Flask ===
def require_permission(action):
    """
    Protège une route Flask selon la permission demandée.
    Exemple :
        @app.route('/admin')
        @require_permission('admin')
        def admin_panel():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import session
            username = session.get("user")
            if not username:
                return redirect(url_for("login"))

            authz = AuthorizationEnforcer()
            if not authz.can_access(username, action):
                authz.logger.warning(f"Unauthorized access by {username} on {action}")
                return abort(403)

            return f(*args, **kwargs)
        return wrapper
    return decorator
