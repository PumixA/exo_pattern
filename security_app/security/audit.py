import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
import json
import os
from typing import Optional, Dict, Any


class SecurityAuditLogger:
    """
    Logger d’audit sécurité :
    - Format JSON sur une seule ligne par événement
    - Écrit dans logs/security_audit.log (rotatif) + console
    - Méthodes helpers (login_attempt, access_denied, permission_change, anomaly)
    """

    def __init__(
        self,
        log_dir: str = None,
        filename: str = "security_audit.log",
        max_bytes: int = 1_000_000,
        backup_count: int = 5,
        also_console: bool = True,
    ):
        # Résolution dossier logs
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../security_app
        repo_root = os.path.dirname(project_root)                                   # .../exo_pattern
        default_logs = os.path.join(repo_root, "logs")

        self.log_dir = log_dir or default_logs
        os.makedirs(self.log_dir, exist_ok=True)
        log_path = os.path.join(self.log_dir, filename)

        self.logger = logging.getLogger("security_audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # évite double logs si root handler

        # Nettoie handlers existants si réimport
        if self.logger.handlers:
            self.logger.handlers.clear()

        # Handler fichier rotatif
        file_handler = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
        file_handler.setLevel(logging.INFO)
        # Pas de formatter textuel : on push déjà du JSON prêt
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(file_handler)

        # Handler console (optionnel)
        if also_console:
            stream = logging.StreamHandler()
            stream.setLevel(logging.INFO)
            stream.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(stream)

    # ---------- API publique ----------

    def log_event(
        self,
        event_type: str,
        user: Optional[str] = None,
        severity: str = "INFO",
        ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        path: Optional[str] = None,
    ):
        """
        Écrit un événement JSON.
        """
        payload = {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "user": user or "anonymous",
            "severity": severity.upper(),
            "ip": ip,
            "path": path,
            "details": details or {},
        }
        self.logger.info(json.dumps(payload, ensure_ascii=False))

    # Helpers d’événements fréquents

    def login_attempt(self, user: str, ip: str, success: bool, locked: bool = False):
        self.log_event(
            event_type="LOGIN_ATTEMPT",
            user=user,
            ip=ip,
            severity="INFO" if success else ("WARNING" if not locked else "ERROR"),
            details={"success": success, "locked": locked},
        )

    def logout(self, user: str, ip: str):
        self.log_event("LOGOUT", user=user, ip=ip, severity="INFO")

    def access_denied(self, user: Optional[str], ip: str, path: str, reason: str = "forbidden"):
        self.log_event(
            "ACCESS_DENIED",
            user=user,
            ip=ip,
            path=path,
            severity="WARNING",
            details={"reason": reason},
        )

    def permission_change(self, admin_user: str, target_user: str, before: Any, after: Any, ip: str):
        self.log_event(
            "PERMISSION_CHANGE",
            user=admin_user,
            ip=ip,
            severity="INFO",
            details={"target": target_user, "before": before, "after": after},
        )

    def anomaly(self, user: Optional[str], ip: str, kind: str, data: Dict[str, Any]):
        self.log_event(
            "ANOMALY",
            user=user,
            ip=ip,
            severity="WARNING",
            details={"kind": kind, **(data or {})},
        )
