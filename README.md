# Multi-Function Web Security Tool (Milestone 1)

A Milestone 1 project demonstrating core Week 1–3 security scripting concepts through two interfaces:

1. Desktop GUI (Tkinter)
2. Web App (Flask + Jinja Templates)

Features

1. Password Strength Checker

- Accepts a password input
- Rates strength (Very Weak → Very Strong)
- Provides improvement tips (length, uppercase, lowercase, digits, special characters)
- (Desktop version may include a live checklist while typing)

2. Secure Password Generator + SHA-256 Hashing + Save to File

- Generates a secure random password (8–16 characters)
- Includes at least: 1 uppercase, 1 lowercase, 1 digit, 1 special character
- Hashes the password using SHA-256\*
- Saves output to `passwords.txt` with timestamp (append mode)

3. Web Form Input Validator + Sanitizer
   Validates and sanitizes:

- Full Name
- Email Address
- Username
- Message / Comment

Security checks include:

- Input sanitization (removes/cleans unsafe characters and suspicious patterns)
- Pattern detection/removal for common SQL keywords and classic injection patterns (coursework-level)
- HTML/script pattern handling (basic filtering; plus Jinja template auto-escaping prevents raw HTML from rendering by default)

> Note: These checks are designed for coursework/demo purposes and do not replace full production security controls.

Project Structure
Milestone 1 Tool/
├─ app.py # Desktop GUI (Tkinter)
├─ web_app.py # Web App (Flask)
├─ constants.py
├─ password_tools.py
├─ form_tools.py
├─ requirements.txt
├─ Templates/
│ ├─ base.html
│ ├─ index.html
│ ├─ strength.html
│ ├─ generator.html
│ └─ form_validator.html
├─ static/
│ └─ style.css
└─ README.md

Requirements

Install dependencies (recommended in a virtual environment):

```bash
py -m pip install -r requirements.txt
```
