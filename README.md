# Password Strength Checker

A Python command-line tool that evaluates password strength, suggests stronger alternatives, and prevents reuse of old passwords using a SQLite database with salted hashes.

## Features

- **Length check:** minimum 8 characters, with bonus points at 12 and 16+
- **Complexity check:** lowercase, uppercase, digits and special characters
- **Uniqueness check:** rejects common passwords (e.g. `password`, `123456`) and flags repeated characters and sequences (`aaa`, `1234`, `abcd`)
- **Entropy calculation:** estimates strength in bits (`length x log2(character pool size)`)
- **Stronger suggestions:** generates random secure passwords using Python's `secrets` module
- **Reuse prevention:** stores only salted PBKDF2-SHA256 hashes in SQLite and blocks previously used passwords per user

## Requirements

- Python 3.8 or newer
- No external libraries (standard library only)

## How to Run

```bash
git clone https://github.com/ferdinandgarson/password-strength-checker.git
cd password-strength-checker
python password_checker.py
```

On Mac/Linux use `python3 password_checker.py`.

1. Enter a username.
2. Enter a password (input is hidden).
3. View the score, entropy and issues found.
4. Weak or reused passwords get suggestions and a retry prompt. Strong, new passwords are stored as salted hashes.

## Sample Output

```
=== Password Strength Checker ===
Username: gary
Enter a new password (hidden):

Strength: Very Strong (100/100) | Entropy: 157.3 bits

Password accepted and stored securely (salted hash).
```

```
Strength: Very Weak (10/100) | Entropy: 28.2 bits
  - Add uppercase letters.
  - Add digits.
  - Add special characters (!@#$...).
  - This is a very common password.

Suggested stronger passwords:
  <3 random 16-character passwords>
```

## Cryptography Concepts Used

| Concept | Where it is used |
|---|---|
| **Hashing** | Passwords are never stored in plain text; only SHA-256 based hashes are saved |
| **Salting** | A random 16-byte salt per password defeats rainbow-table attacks |
| **Key stretching (PBKDF2)** | 200,000 iterations make brute-force attacks slow |
| **Entropy** | Measures how unpredictable a password is |
| **CSPRNG (`secrets`)** | Cryptographically secure generation of suggested passwords |
| **Constant-time comparison** | `secrets.compare_digest` avoids timing attacks |

## Project Structure

```
password-strength-checker/
|-- password_checker.py   # main program
|-- README.md             # documentation
|-- .gitignore            # keeps passwords.db out of the repo
```

## Author

Ferdinand Garson L, B.Tech CSE (AI), Karunya University
