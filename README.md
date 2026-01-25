# Multi-Function Web Security Tool (Milestone 1)

A simple Tkinter-based security tool that demonstrates Week 1–3 concepts:
password strength assessment, secure password generation + hashing, and web form input validation/sanitization.

## Features
1. **Password Strength Checker**
   - Rates a password (Very Weak → Very Strong)
   - Gives improvement tips (length, uppercase, lowercase, digit, special character)

2. **Secure Password Generator + SHA-256 Hash + Save to File**
   - Generates a random password (8–16 characters)
   - Includes at least 1 uppercase, 1 lowercase, 1 number, and 1 special character
   - Hashes the password using **SHA-256**
   - Saves timestamp + password + hash to `passwords.txt` (append mode)
   - Includes **Copy Password** and **Show/Hide Password** buttons

3. **Web Form Validator + Sanitizer**
   - Validates and sanitizes four fields:
     - Full Name
     - Email Address
     - Username
     - Message/Comment
   - Detects and neutralizes suspicious patterns (basic XSS/HTML + SQL keyword patterns)
   - Prints validation results, sanitized output, and sanitization summary

## Requirements
- Python 3.x
- Tkinter (included by default with most Python installations)

## How to Run
1. Open a terminal in the project folder.
2. Run:
   ```bash
   python app.py
