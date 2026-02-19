import hashlib
import hmac
import os

class PasswordSecurity:
    MIN_LENGTH = 8

    def hash_password(self, password: str) -> str:
        salt = os.urandom(16).hex()
        salted = salt + password
        digest = hashlib.sha256(salted.encode()).hexdigest()
        return f"{salt}:{digest}"

    def verify_hash(self, password: str, stored_hash: str) -> bool:
        try:
            salt, original_digest = stored_hash.split(":", 1)
        except ValueError:
            return False

        salted = salt + password
        candidate_digest = hashlib.sha256(salted.encode()).hexdigest()
        return hmac.compare_digest(candidate_digest, original_digest)

    def check_strength(self, password: str) -> tuple[bool, list[str]]:
        issues = []
        if len(password) < self.MIN_LENGTH:
            issues.append(f"  ✗ Too short — must be at least {self.MIN_LENGTH} characters")
        if not any(ch.isupper() for ch in password):
            issues.append("  ✗ Must contain at least one UPPERCASE letter")
        if not any(ch.islower() for ch in password):
            issues.append("  ✗ Must contain at least one lowercase letter")
        if not any(ch.isdigit() for ch in password):
            issues.append("  ✗ Must contain at least one number (0-9)")
        special = set("!@#$%^&*()-_=+[]{}|;:',.<>?/`~")
        if not any(ch in special for ch in password):
            issues.append("  ✗ Must contain at least one special character (!@#$ etc.)")
        return (len(issues) == 0), issues

    def strength_label(self, password: str) -> str:
        passed, issues = self.check_strength(password)
        score = 5 - len(issues)
        if score <= 1: return "VERY WEAK"
        elif score == 2: return "WEAK"
        elif score == 3: return "MODERATE"
        elif score == 4: return "STRONG"
        else: return "VERY STRONG"

class User:
    def __init__(self, username: str, hashed_password: str):
        self.username = username
        self.hashed_password = hashed_password
        self.failed_attempts = 0
        self.is_locked = False

class AuthenticationSystem:
    MAX_FAILED_ATTEMPTS = 3

    def __init__(self):
        self._users: dict[str, User] = {}
        self._security = PasswordSecurity()

    def register(self, username: str, password: str) -> bool:
        key = username.strip().lower()
        if key in self._users:
            print(f"[!] Username '{username}' is already taken.")
            return False
        passed, issues = self._security.check_strength(password)
        if not passed:
            print("\n[!] Registration FAILED:")
            for issue in issues: print(issue)
            return False
        self._users[key] = User(username.strip(), self._security.hash_password(password))
        print(f"\n[✓] User '{username}' registered successfully.")
        return True

    def login(self, username: str, password: str) -> bool:
        key = username.strip().lower()
        user = self._users.get(key)
        if user is None:
            print("\n[✗] Invalid username or password.")
            return False
        if user.is_locked:
            print(f"\n[🔒] Account '{username}' is LOCKED.")
            return False
        if self._security.verify_hash(password, user.hashed_password):
            user.failed_attempts = 0
            print(f"\n[✓] Welcome back, {user.username}! Access GRANTED.")
            return True
        else:
            user.failed_attempts += 1
            remaining = self.MAX_FAILED_ATTEMPTS - user.failed_attempts
            if remaining <= 0:
                user.is_locked = True
                print(f"[🔒] Account '{username}' has been LOCKED.")
            else:
                print(f"[✗] Invalid credentials. {remaining} attempt(s) left.")
            return False

def main():
    auth = AuthenticationSystem()
    print("--- Secure Authentication System ---")
    
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Select an option: ")
        
        if choice == '1':
            u = input("Enter new username: ")
            p = input("Enter new password: ")
            auth.register(u, p)
        elif choice == '2':
            u = input("Username: ")
            p = input("Password: ")
            auth.login(u, p)
        elif choice == '3':
            print("Exiting system...")
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()