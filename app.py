import os
import time
import secrets
import smtplib
import ssl
import re

from email.message import EmailMessage
from flask import Flask, render_template, request, jsonify, session


app = Flask(__name__)

# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-before-deployment"
)

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")

OTP_EXPIRY_SECONDS = 180       # OTP valid for 3 minutes
RESEND_WAIT_SECONDS = 60       # Wait 60 seconds before requesting again
MAX_ATTEMPTS = 5               # Maximum wrong OTP attempts


# Temporary storage for our demo.
# OTPs disappear when the Flask server is restarted.
otp_store = {}


# --------------------------------------------------
# SEND EMAIL
# --------------------------------------------------

def send_otp_email(receiver_email, otp):

    message = EmailMessage()

    message["Subject"] = "Your Email OTP Login Code"
    message["From"] = GMAIL_ADDRESS
    message["To"] = receiver_email

    message.set_content(
        f"""
Hello,

Your login OTP is:

{otp}

This OTP is valid for 3 minutes.

If you did not request this code, you can ignore this email.

Thank you.
"""
    )

    # Connect to Gmail SMTP
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context
    ) as server:

        server.login(
            GMAIL_ADDRESS,
            GMAIL_APP_PASSWORD
        )

        server.send_message(message)


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    return render_template("index.html")


# --------------------------------------------------
# SEND OTP
# --------------------------------------------------

@app.route("/send-otp", methods=["POST"])
def send_otp():

    # Check Gmail settings
    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:

        return jsonify({
            "error": "Gmail configuration is missing."
        }), 500


    # Get JSON data
    data = request.get_json(silent=True) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()


    # Check email
    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):

        return jsonify({
            "error": "Please enter a valid email address."
        }), 400


    now = time.time()

    previous = otp_store.get(email)


    # Prevent spam requests
    if previous:

        seconds_since_last = now - previous["sent_at"]

        if seconds_since_last < RESEND_WAIT_SECONDS:

            remaining = int(
                RESEND_WAIT_SECONDS -
                seconds_since_last
            )

            return jsonify({
                "error":
                    f"Please wait {remaining} seconds before requesting another OTP."
            }), 429


    # Generate 6-digit OTP
    otp = f"{secrets.randbelow(1_000_000):06d}"


    # Send email
    try:

        send_otp_email(
            email,
            otp
        )

    except Exception:

        app.logger.exception(
            "Gmail sending failed"
        )

        return jsonify({
            "error":
                "Could not send email. Check Gmail configuration."
        }), 502


    # Save OTP
    otp_store[email] = {

        "otp": otp,

        "expires":
            now + OTP_EXPIRY_SECONDS,

        "sent_at":
            now,

        "attempts":
            0
    }


    return jsonify({

        "message":
            "OTP sent! Check your email inbox."
    })


# --------------------------------------------------
# VERIFY OTP
# --------------------------------------------------

@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    data = request.get_json(
        silent=True
    ) or {}


    email = data.get(
        "email",
        ""
    ).strip().lower()


    entered_otp = data.get(
        "otp",
        ""
    ).strip()


    record = otp_store.get(email)


    # No OTP
    if not record:

        return jsonify({
            "error":
                "No active OTP. Please request a new OTP."
        }), 400


    # OTP expired
    if time.time() >= record["expires"]:

        otp_store.pop(
            email,
            None
        )

        return jsonify({
            "error":
                "OTP expired. Please request a new OTP."
        }), 400


    # Too many attempts
    if record["attempts"] >= MAX_ATTEMPTS:

        otp_store.pop(
            email,
            None
        )

        return jsonify({
            "error":
                "Too many attempts. Request a new OTP."
        }), 429


    # Count this attempt
    record["attempts"] += 1


    # Check format
    if not re.fullmatch(
        r"\d{6}",
        entered_otp
    ):

        return jsonify({
            "error":
                "OTP must contain exactly 6 digits."
        }), 400


    # Check OTP
    if entered_otp != record["otp"]:

        return jsonify({
            "error":
                "Incorrect OTP."
        }), 400


    # OTP is correct
    otp_store.pop(
        email,
        None
    )


    # Create login session
    session.clear()

    session["email"] = email


    return jsonify({

        "message":
            "Login successful!",

        "email":
            email
    })


# --------------------------------------------------
# CHECK LOGIN
# --------------------------------------------------

@app.route("/me")
def me():

    if "email" not in session:

        return jsonify({
            "logged_in": False
        }), 401


    return jsonify({

        "logged_in": True,

        "email":
            session["email"]
    })


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route(
    "/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({

        "message":
            "Logged out successfully."
    })


# --------------------------------------------------
# START SERVER
# --------------------------------------------------

if __name__ == "__main__":

    app.config.update({

        "SESSION_COOKIE_HTTPONLY": True,

        "SESSION_COOKIE_SAMESITE": "Lax"
    })


    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False
    )