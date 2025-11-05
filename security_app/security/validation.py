import re
import html


class InputValidator:

    # === VALIDATION PAR CHAMP ===

    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_username(username: str) -> bool:
        pattern = r"^[a-zA-Z0-9]{3,20}$"
        return re.match(pattern, username) is not None

    @staticmethod
    def validate_password(password: str) -> bool:
        # Min 8 caractères, 1 maj, 1 min, 1 chiffre, 1 spécial
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        return re.match(pattern, password) is not None

    @staticmethod
    def validate_age(age: str) -> bool:
        try:
            age = int(age)
            return 13 <= age <= 120
        except ValueError:
            return False

    # === SANITIZATION / PROTECTION XSS ===

    @staticmethod
    def sanitize_html(text: str) -> str:
        """Neutralise les balises HTML (anti-XSS basic)"""
        return html.escape(text)

    # === DÉTECTION SQL INJECTION SIMPLIFIÉE ===

    @staticmethod
    def detect_sql_injection(text: str) -> bool:
        """Renvoie True si un pattern d'injection SQL est détecté"""
        patterns = [
            r"(--|\bOR\b|\bAND\b|\bUNION\b)",
            r"(;|/\*|\*/|@@|@)",
            r"(\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)"
        ]
        lowered = text.lower()
        return any(re.search(p, lowered, re.IGNORECASE) for p in patterns)
