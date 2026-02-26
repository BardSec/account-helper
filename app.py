"""
AD Password Reset Tool — Flask application entry point.

Configuration is loaded from environment variables (or a .env file).
Required:
  AD_SERVER   — LDAP URL, e.g. ldaps://dc01.corp.com
  AD_BASE_DN  — Search base, e.g. DC=corp,DC=com
Optional:
  AD_SKIP_TLS_VERIFY — Set to "true" only for dev/test with self-signed certs (default: false)
  SECRET_KEY         — Flask session secret (default: insecure dev value, always override in prod)
  PORT               — Port to listen on (default: 5000)
"""
import os
from flask import Flask, render_template, request, flash, redirect, url_for
from dotenv import load_dotenv
from ad import ADClient, ADError

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

AD_SERVER = os.environ.get("AD_SERVER", "")
AD_BASE_DN = os.environ.get("AD_BASE_DN", "")
AD_SKIP_TLS_VERIFY = os.environ.get("AD_SKIP_TLS_VERIFY", "false").lower() == "true"


@app.route("/", methods=["GET", "POST"])
def index():
    if not AD_SERVER or not AD_BASE_DN:
        return render_template(
            "index.html",
            config_error="AD_SERVER and AD_BASE_DN must be set in the .env file before use.",
        )

    if request.method == "GET":
        return render_template("index.html")

    # --- Collect form fields ---
    tech_username   = request.form.get("tech_username", "").strip()
    tech_password   = request.form.get("tech_password", "")
    target_username = request.form.get("target_username", "").strip()
    new_password    = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    unlock          = "unlock" in request.form
    force_change    = "force_change" in request.form

    # --- Basic client-side-style validation on the server ---
    if not all([tech_username, tech_password, target_username, new_password, confirm_password]):
        flash("All fields are required.", "error")
        return render_template("index.html", form=request.form)

    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "error")
        return render_template("index.html", form=request.form)

    # --- Attempt the reset ---
    try:
        client = ADClient(AD_SERVER, AD_BASE_DN, skip_tls_verify=AD_SKIP_TLS_VERIFY)
        client.reset_password(
            tech_username=tech_username,
            tech_password=tech_password,
            target_username=target_username,
            new_password=new_password,
            unlock=unlock,
            force_change=force_change,
        )
    except ADError as exc:
        flash(str(exc), "error")
        return render_template("index.html", form=request.form)

    return render_template(
        "index.html",
        success=True,
        target_username=target_username,
        did_unlock=unlock,
        did_force_change=force_change,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
