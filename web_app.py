import os
from flask import Flask, render_template, request

from password_tools import (
    generate_password,
    hash_password_sha256,
    save_password_entry,
    check_password_strength,
    get_timestamp,
)
from form_tools import (
    sanitize_text_basic,
    remove_prohibited_patterns,
    validate_full_name,
    validate_email,
    validate_username,
    validate_message,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")


@app.get("/")
def index():
    return render_template("index.html")


@app.route("/strength", methods=["GET", "POST"])
def strength():
    result = None

    if request.method == "POST":
        pw = request.form.get("password", "")
        rating, tips = check_password_strength(pw)

        result = {
            "rating": rating,
            "tips": tips,
        }

    return render_template("strength.html", result=result)


@app.route("/generator", methods=["GET", "POST"])
def generator():
    result = None
    error = None

    if request.method == "POST":
        password = generate_password()
        pw_hash = hash_password_sha256(password)
        timestamp = get_timestamp()

        try:
            save_password_entry(timestamp, password, pw_hash)
        except Exception as e:
            error = f"Could not save to passwords.txt: {e}"

        result = {
            "timestamp": timestamp,
            "password": password,
            "hash": pw_hash,
            "saved": (error is None),
        }

    return render_template("generator.html", result=result, error=error)


@app.route("/form-validator", methods=["GET", "POST"])
def form_validator():
    form_values = {"full_name": "", "email": "", "username": "", "message": ""}
    output = None

    if request.method == "POST":
        # raw values for redisplay
        form_values["full_name"] = request.form.get("full_name", "")
        form_values["email"] = request.form.get("email", "")
        form_values["username"] = request.form.get("username", "")
        form_values["message"] = request.form.get("message", "")

        # 1) Sanitize
        fn_clean, fn_notes = sanitize_text_basic(form_values["full_name"])
        em_clean, em_notes = sanitize_text_basic(form_values["email"])
        un_clean, un_notes = sanitize_text_basic(form_values["username"])

        msg_clean, msg_notes1 = sanitize_text_basic(form_values["message"])
        msg_clean, msg_notes2 = remove_prohibited_patterns(msg_clean)
        msg_notes = msg_notes1 + msg_notes2

        # 2) Validate sanitized values
        fn_ok, fn_errs = validate_full_name(fn_clean)
        em_ok, em_errs = validate_email(em_clean)
        un_ok, un_errs = validate_username(un_clean)
        msg_ok, msg_errs = validate_message(msg_clean)

        validation_lines = []

        if fn_ok:
            validation_lines.append("- Full Name: Valid")
        else:
            validation_lines.append(f"- Full Name: Invalid ({fn_errs[0]})")
            validation_lines.extend([f"  * {e}" for e in fn_errs])

        if em_ok:
            validation_lines.append("- Email: Valid")
        else:
            validation_lines.append(f"- Email: Invalid ({em_errs[0]})")
            validation_lines.extend([f"  * {e}" for e in em_errs])

        if un_ok:
            validation_lines.append("- Username: Valid")
        else:
            validation_lines.append(f"- Username: Invalid ({un_errs[0]})")
            validation_lines.extend([f"  * {e}" for e in un_errs])

        if msg_ok:
            if msg_notes:
                validation_lines.append(
                    f"- Message: Sanitized ({msg_notes[0]})")
            else:
                validation_lines.append("- Message: Valid")
        else:
            validation_lines.append(f"- Message: Invalid ({msg_errs[0]})")
            validation_lines.extend([f"  * {e}" for e in msg_errs])

        summary_lines = []
        for label, notes in [
            ("Full Name", fn_notes),
            ("Email", em_notes),
            ("Username", un_notes),
            ("Message", msg_notes),
        ]:
            if notes:
                summary_lines.append(
                    f"- {label}: Unsafe characters detected and cleaned.")
                summary_lines.extend([f"  * {n}" for n in notes])

        output = {
            "validation": validation_lines,
            "sanitized": {
                "full_name": fn_clean,
                "email": em_clean,
                "username": un_clean,
                "message": msg_clean,
            },
            "summary": summary_lines,
        }

    return render_template("form_validator.html", form=form_values, output=output)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
