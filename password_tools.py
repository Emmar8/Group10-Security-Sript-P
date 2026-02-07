# password_tools.py
import re
import secrets
import string
import hashlib
from datetime import datetime
from constants import SPECIALS

def generate_password() -> str:
    length = secrets.choice(range(8, 17))

    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(SPECIALS),
    ]

    all_allowed = string.ascii_letters + string.digits + SPECIALS
    chars += [secrets.choice(all_allowed) for _ in range(length - 4)]

    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

def hash_password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def get_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def save_password_entry(timestamp: str, password: str, password_hash: str, filename: str = "passwords.txt") -> None:
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Password: {password}\n")
        f.write(f"Hash: {password_hash}\n")
        f.write("-" * 40 + "\n")

def check_password_strength(password: str) -> tuple[str, list[str]]:
    tips = []
    score = 0

    if len(password) >= 12:
        score += 1
    else:
        tips.append("Use at least 12 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        tips.append("Add an uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        tips.append("Add a lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        tips.append("Add a number.")

    # Use assignment SPECIALS set (more accurate than [^\w\s])
    specials_pattern = "[" + re.escape(SPECIALS) + "]"
    if re.search(specials_pattern, password):
        score += 1
    else:
        tips.append("Add a special character from the allowed set.")

    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
    return labels[score], tips
