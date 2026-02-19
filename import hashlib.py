import hashlib


# -----------------------------
# Class 1: Account
# Represents a system user
# -----------------------------
class Account:
    def __init__(self, username, password_hash):
        # Store username
        self.username = username
        
        # Store only hashed password (never plain password)
        self.password_hash = password_hash
        
        # Track failed login attempts (basic security feature)
        self.failed_attempts = 0


# -----------------------------
# Class 2: SecurityUtility
# Handles password validation and hashing
# -----------------------------
class SecurityUtility:

    def validate_password(self, password):
        """
        Checks password strength requirements:
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        """

        if len(password) < 8:
            return False, "Password must be at least 8 characters long."

        if not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter."

        if not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter."

        if not any(char.isdigit() for char in password):
            return False, "Password must contain at least one number."

        return True, "Password is strong."

    def hash_password(self, password):
        """
        Converts password into SHA-256 hash.
        This ensures secure storage.
        """
        return hashlib.sha256(password.encode()).hexdigest()


# -----------------------------
# Class 3: LoginManager
# Manages registration and authentication
# -----------------------------
class LoginManager:

    def __init__(self):
        # Simulated secure storage (dictionary database)
        self.users = {}
        self.security = SecurityUtility()

    def register(self):
        print("\n--- User Registration ---")
        username = input("Enter username: ")
        password = input("Enter password: ")

        # Validate password strength
        valid, message = self.security.validate_password(password)

        if not valid:
            print("Registration failed:", message)
            return

        # Hash password before storing
        password_hash = self.security.hash_password(password)

        # Store user securely
        self.users[username] = Account(username, password_hash)

        print("Registration successful.")

    def login(self):
        print("\n--- User Login ---")
        username = input("Enter username: ")
        password = input("Enter password: ")

        # Check if user exists
        if username not in self.users:
            print("Access denied: User does not exist.")
            return

        account = self.users[username]

        # Basic access control: lock after 3 failed attempts
        if account.failed_attempts >= 3:
            print("Account locked due to multiple failed attempts.")
            return

        # Hash entered password
        password_hash = self.security.hash_password(password)

        # Compare hashes
        if password_hash == account.password_hash:
            print("Login successful. Access granted.")
            account.failed_attempts = 0  # reset counter
        else:
            account.failed_attempts += 1
            print("Incorrect password.")
            print("Failed attempts:", account.failed_attempts)


# Main Program Execution
def main():
    system = LoginManager()

    while True:
        print("\n==== Authentication System ====")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            system.register()
        elif choice == "2":
            system.login()
        elif choice == "3":
            print("Exiting system...")
            break
        else:
            print("Invalid choice. Try again.")


# Run the program
main()

