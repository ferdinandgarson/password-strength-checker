 
import getpass
import hashlib
import math
import os
import re
import secrets
import sqlite3
import string
 
DB_FILE = "passwords.db"
ITERATIONS = 200_000
 
# Small sample list; for real use, load a bigger one (e.g. rockyou top 10k)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "welcome", "letmein",
    "monkey", "dragon", "football", "login", "passw0rd", "qwerty123",
}
 
 
# ---------- Database (hashing + reuse prevention) ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS password_history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL,
               salt BLOB NOT NULL,
               hash BLOB NOT NULL,
               created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    conn.commit()
    return conn
 
 
def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
 
 
def was_used_before(conn, username: str, password: str) -> bool:
    rows = conn.execute(
        "SELECT salt, hash FROM password_history WHERE username = ?", (username,)
    ).fetchall()
    return any(
        secrets.compare_digest(hash_password(password, salt), stored)
        for salt, stored in rows
    )
 
 
def save_password(conn, username: str, password: str):
    salt = os.urandom(16)
    conn.execute(
        "INSERT INTO password_history (username, salt, hash) VALUES (?, ?, ?)",
        (username, salt, hash_password(password, salt)),
    )
    conn.commit()
 
 
# ---------- Strength analysis ----------
def calculate_entropy(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[^\w\s]", password): pool += 32
    return len(password) * math.log2(pool) if pool else 0.0
 
 
def check_password(password: str):
    """Returns (score 0-100, label, list of issues)."""
    issues, score = [], 0
 
    # Length
    if len(password) < 8:
        issues.append("Too short (minimum 8 characters).")
    else:
        score += 20
        if len(password) >= 12: score += 15
        if len(password) >= 16: score += 10
 
    # Complexity
    checks = [
        (r"[a-z]", "Add lowercase letters."),
        (r"[A-Z]", "Add uppercase letters."),
        (r"\d", "Add digits."),
        (r"[^\w\s]", "Add special characters (!@#$...)."),
    ]
    for pattern, msg in checks:
        if re.search(pattern, password):
            score += 10
        else:
            issues.append(msg)
 
    # Weak patterns
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is a very common password.")
        score = min(score, 10)
    if re.search(r"(.)\1{2,}", password):
        issues.append("Avoid repeating the same character 3+ times.")
        score -= 10
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)", password.lower()):
        issues.append("Avoid sequences like 1234 or abcd.")
        score -= 10
 
    # Entropy bonus
    entropy = calculate_entropy(password)
    if entropy >= 60: score += 15
    elif entropy >= 40: score += 5
 
    score = max(0, min(100, score))
    label = (
        "Very Weak" if score < 30 else
        "Weak" if score < 50 else
        "Medium" if score < 70 else
        "Strong" if score < 90 else
        "Very Strong"
    )
    return score, label, issues
 
 
# ---------- Suggestions ----------
def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd
 
 
def suggest_passwords(count: int = 3):
    return [generate_password() for _ in range(count)]
 
 
# ---------- CLI ----------
def main():
    conn = init_db()
    print("=== Password Strength Checker ===")
    username = input("Username: ").strip()
 
    while True:
        password = getpass.getpass("Enter a new password (hidden): ")
        score, label, issues = check_password(password)
        entropy = calculate_entropy(password)
 
        print(f"\nStrength: {label} ({score}/100) | Entropy: {entropy:.1f} bits")
        for issue in issues:
            print(f"  - {issue}")
 
        if was_used_before(conn, username, password):
            print("  - You have used this password before. Choose a new one.")
            issues.append("reused")
 
        if score < 70 or issues:
            print("\nSuggested stronger passwords:")
            for s in suggest_passwords():
                print(f"  {s}")
            if input("\nTry again? (y/n): ").lower() != "y":
                break
        else:
            save_password(conn, username, password)
            print("\nPassword accepted and stored securely (salted hash).")
            break
 
    conn.close()
 
 
if __name__ == "__main__":
    main()