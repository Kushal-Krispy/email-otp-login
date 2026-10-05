import os
import re
import secrets
import smtplib
import ssl

from datetime import datetime, timezone, timedelta
from email.message import EmailMessage

from flask import Flask, render_template, request, jsonify, session
from supabase import create_client
from werkzeug.security import generate_password_hash, check_password_hash


# ==================================================
# FLASK APP
# ==================================================

app = Flask(__name__)


# ==================================================
# SECRET KEY
# ==================================================

SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing. "
        "Please set the SECRET_KEY environment variable."
    )

app.secret_key = SECRET_KEY


# ==================================================
# GMAIL SETTINGS
# ==================================================

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")


# ==================================================
# SUPABASE SETTINGS
# ==================================================

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get(
    "SUPABASE_SERVICE_ROLE_KEY"
)

if not SUPABASE_URL:
    raise RuntimeError(
        "SUPABASE_URL is missing."
    )

if not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError(
        "SUPABASE_SERVICE_ROLE_KEY is missing."
    )


# ==================================================
# SUPABASE CLIENT
# ==================================================

supabase = create_client(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
)


# ==================================================
# OTP SETTINGS
# ==================================================

OTP_EXPIRY_SECONDS = 180
RESEND_WAIT_SECONDS = 60
MAX_ATTEMPTS = 5


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def normalize_dob(dob):
    """
    Convert user-entered DD-MM-YYYY into database format YYYY-MM-DD.
    """
    try:
        parsed = datetime.strptime(
            dob.strip(),
            "%d-%m-%Y"
        )

        return parsed.strftime(
            "%Y-%m-%d"
        )

    except ValueError:
        return None


def is_valid_email(email):
    return bool(
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        )
    )


def utc_now():
    return datetime.now(timezone.utc)


def parse_supabase_datetime(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def generate_otp():
    return f"{secrets.randbelow(1_000_000):06d}"


def get_latest_active_otp(email, purpose):

    response = (
        supabase
        .table("otp_verifications")
        .select("*")
        .eq("email", email)
        .eq("purpose", purpose)
        .is_("consumed_at", "null")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if response.data:
        return response.data[0]

    return None


def consume_otp(otp_id):

    (
        supabase
        .table("otp_verifications")
        .update({
            "consumed_at": utc_now().isoformat()
        })
        .eq("id", otp_id)
        .execute()
    )


def create_login_session(user):

    session.clear()

    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session["name"] = user["name"]


def update_user_login_status(user_id):

    (
        supabase
        .table("users")
        .update({
            "is_logged_in": True,
            "last_login_at": utc_now().isoformat()
        })
        .eq("id", user_id)
        .execute()
    )


# ==================================================
# SEND REGISTRATION OTP EMAIL
# ==================================================

def send_registration_otp_email(
    receiver_email,
    otp
):

    message = EmailMessage()

    message["Subject"] = (
        "Verify Your Email - Registration OTP"
    )

    message["From"] = GMAIL_ADDRESS
    message["To"] = receiver_email

    message.set_content(
        f"""
Hello,

Your registration verification OTP is:

{otp}

This OTP is valid for 3 minutes.

If you did not request registration, you can ignore this email.

Thank you.
"""
    )

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


# ==================================================
# SEND LOGIN OTP EMAIL
# ==================================================

def send_otp_email(
    receiver_email,
    otp
):

    message = EmailMessage()

    message["Subject"] = (
        "Your Email OTP Login Code"
    )

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


# ==================================================
# HOME PAGE
# ==================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==================================================
# REGISTER
# ==================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    # --------------------------------------------------
    # CHECK GMAIL CONFIGURATION
    # --------------------------------------------------

    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:

        return jsonify({
            "error":
                "Gmail configuration is missing."
        }), 500


    # --------------------------------------------------
    # GET REQUEST DATA
    # --------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    name = data.get(
        "name",
        ""
    ).strip()

    date_of_birth = data.get(
        "date_of_birth",
        ""
    ).strip()

    college_name = data.get(
        "college_name",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip().lower()


    # --------------------------------------------------
    # VALIDATE NAME
    # --------------------------------------------------

    if not name:

        return jsonify({
            "error":
                "Name is required."
        }), 400


    # --------------------------------------------------
    # VALIDATE DATE OF BIRTH
    # --------------------------------------------------

    if not date_of_birth:

        return jsonify({
            "error":
                "Date of birth is required."
        }), 400


    # Check DD-MM-YYYY format before sending OTP
    date_of_birth_normalized = normalize_dob(
        date_of_birth
    )

    if not date_of_birth_normalized:

        return jsonify({
            "error":
                "Date of birth must be in DD-MM-YYYY format."
        }), 400


    # --------------------------------------------------
    # VALIDATE COLLEGE
    # --------------------------------------------------

    if not college_name:

        return jsonify({
            "error":
                "College name is required."
        }), 400


    # --------------------------------------------------
    # VALIDATE EMAIL
    # --------------------------------------------------

    if not is_valid_email(email):

        return jsonify({
            "error":
                "Please enter a valid email address."
        }), 400


    # --------------------------------------------------
    # CHECK EXISTING USER
    # --------------------------------------------------

    try:

        response = (
            supabase
            .table("users")
            .select("id")
            .eq("email", email)
            .limit(1)
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not check existing user"
        )

        return jsonify({
            "error":
                "Could not check database. Please try again."
        }), 500


    if response.data:

        return jsonify({
            "error":
                "This email already exists."
        }), 409


    # --------------------------------------------------
    # CHECK PREVIOUS REGISTRATION OTP
    # --------------------------------------------------

    try:

        previous = get_latest_active_otp(
            email,
            "registration"
        )

    except Exception:

        app.logger.exception(
            "Could not check registration OTP"
        )

        return jsonify({
            "error":
                "Could not check OTP status. Please try again."
        }), 500


    # --------------------------------------------------
    # RESEND WAIT CHECK
    # --------------------------------------------------

    if previous:

        previous_time = parse_supabase_datetime(
            previous["created_at"]
        )

        seconds_since_last = (
            utc_now() - previous_time
        ).total_seconds()

        if seconds_since_last < RESEND_WAIT_SECONDS:

            remaining = max(
                1,
                int(
                    RESEND_WAIT_SECONDS
                    - seconds_since_last
                )
            )

            return jsonify({
                "error":
                    f"Please wait {remaining} seconds before requesting another OTP."
            }), 429


    # --------------------------------------------------
    # GENERATE OTP
    # --------------------------------------------------

    otp = generate_otp()


    # --------------------------------------------------
    # HASH OTP
    # --------------------------------------------------

    otp_hash = generate_password_hash(
        otp
    )


    # --------------------------------------------------
    # OTP EXPIRATION
    # --------------------------------------------------

    expires_at = (
        utc_now()
        + timedelta(
            seconds=OTP_EXPIRY_SECONDS
        )
    )


    # --------------------------------------------------
    # SAVE OTP
    # --------------------------------------------------

    try:

        insert_response = (
            supabase
            .table("otp_verifications")
            .insert({
                "email": email,
                "otp_hash": otp_hash,
                "purpose": "registration",
                "expires_at": expires_at.isoformat(),
                "attempts": 0
            })
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not save registration OTP"
        )

        return jsonify({
            "error":
                "Could not save OTP. Please try again."
        }), 500


    # --------------------------------------------------
    # SEND EMAIL
    # --------------------------------------------------

    try:

        send_registration_otp_email(
            email,
            otp
        )

    except Exception:

        app.logger.exception(
            "Registration Gmail sending failed"
        )

        # Disable OTP if email could not be sent
        try:

            if insert_response.data:

                otp_id = insert_response.data[0]["id"]

                consume_otp(
                    otp_id
                )

        except Exception:

            app.logger.exception(
                "Could not disable failed registration OTP"
            )

        return jsonify({
            "error":
                "Could not send registration email. Check Gmail configuration."
        }), 502


    # --------------------------------------------------
    # SUCCESS
    # --------------------------------------------------

    return jsonify({
        "message":
            "Registration OTP sent! Check your email inbox.",
        "email":
            email
    }), 200


# ==================================================
# VERIFY REGISTRATION OTP
# ==================================================

@app.route(
    "/verify-registration",
    methods=["POST"]
)
def verify_registration():

    # --------------------------------------------------
    # GET REQUEST DATA
    # --------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    name = data.get(
        "name",
        ""
    ).strip()

    date_of_birth = data.get(
        "date_of_birth",
        ""
    ).strip()

    college_name = data.get(
        "college_name",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    entered_otp = data.get(
        "otp",
        ""
    ).strip()


    # --------------------------------------------------
    # VALIDATION
    # --------------------------------------------------

    if not name:

        return jsonify({
            "error":
                "Name is required."
        }), 400


    if not date_of_birth:

        return jsonify({
            "error":
                "Date of birth is required."
        }), 400


    # Validate and normalize DD-MM-YYYY
    date_of_birth_normalized = normalize_dob(
        date_of_birth
    )

    if not date_of_birth_normalized:

        return jsonify({
            "error":
                "Date of birth must be in DD-MM-YYYY format."
        }), 400


    if not college_name:

        return jsonify({
            "error":
                "College name is required."
        }), 400


    if not is_valid_email(email):

        return jsonify({
            "error":
                "Please enter a valid email address."
        }), 400


    if not re.fullmatch(
        r"\d{6}",
        entered_otp
    ):

        return jsonify({
            "error":
                "OTP must contain exactly 6 digits."
        }), 400


    # --------------------------------------------------
    # CHECK EXISTING USER
    # --------------------------------------------------

    try:

        existing_user_response = (
            supabase
            .table("users")
            .select("id")
            .eq("email", email)
            .limit(1)
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not check existing user"
        )

        return jsonify({
            "error":
                "Could not check database. Please try again."
        }), 500


    if existing_user_response.data:

        return jsonify({
            "error":
                "This email already exists."
        }), 409


    # --------------------------------------------------
    # GET REGISTRATION OTP
    # --------------------------------------------------

    try:

        record = get_latest_active_otp(
            email,
            "registration"
        )

    except Exception:

        app.logger.exception(
            "Could not retrieve registration OTP"
        )

        return jsonify({
            "error":
                "Could not retrieve OTP. Please try again."
        }), 500


    if not record:

        return jsonify({
            "error":
                "No active registration OTP. Please request a new OTP."
        }), 400


    # --------------------------------------------------
    # CHECK EXPIRATION
    # --------------------------------------------------

    expires_at = parse_supabase_datetime(
        record["expires_at"]
    )

    if utc_now() >= expires_at:

        try:

            consume_otp(
                record["id"]
            )

        except Exception:

            app.logger.exception(
                "Could not mark expired registration OTP"
            )

        return jsonify({
            "error":
                "OTP expired. Please request a new OTP."
        }), 400


    # --------------------------------------------------
    # CHECK ATTEMPTS
    # --------------------------------------------------

    attempts = record.get(
        "attempts",
        0
    )

    if attempts >= MAX_ATTEMPTS:

        try:

            consume_otp(
                record["id"]
            )

        except Exception:

            app.logger.exception(
                "Could not disable registration OTP"
            )

        return jsonify({
            "error":
                "Too many attempts. Please request a new OTP."
        }), 429


    # --------------------------------------------------
    # INCREASE ATTEMPT COUNT
    # --------------------------------------------------

    new_attempt_count = attempts + 1

    try:

        (
            supabase
            .table("otp_verifications")
            .update({
                "attempts":
                    new_attempt_count
            })
            .eq(
                "id",
                record["id"]
            )
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not update registration OTP attempts"
        )

        return jsonify({
            "error":
                "Could not verify OTP. Please try again."
        }), 500


    # --------------------------------------------------
    # CHECK OTP
    # --------------------------------------------------

    otp_is_correct = check_password_hash(
        record["otp_hash"],
        entered_otp
    )


    if not otp_is_correct:

        if new_attempt_count >= MAX_ATTEMPTS:

            try:

                consume_otp(
                    record["id"]
                )

            except Exception:

                app.logger.exception(
                    "Could not disable registration OTP"
                )

            return jsonify({
                "error":
                    "Too many attempts. Please request a new OTP."
            }), 429

        remaining_attempts = (
            MAX_ATTEMPTS
            - new_attempt_count
        )

        return jsonify({
            "error":
                f"Incorrect OTP. {remaining_attempts} attempts remaining."
        }), 400


    # --------------------------------------------------
    # OTP CORRECT
    # --------------------------------------------------

    try:

        consume_otp(
            record["id"]
        )

    except Exception:

        app.logger.exception(
            "Could not consume registration OTP"
        )

        return jsonify({
            "error":
                "Could not complete verification. Please try again."
        }), 500


    # --------------------------------------------------
    # PASSWORD
    #
    # User requested DOB as the initial password.
    #
    # User enters:
    #
    # DD-MM-YYYY
    #
    # Database/password uses:
    #
    # YYYY-MM-DD
    #
    # IMPORTANT:
    # Raw DOB is NEVER stored as the password.
    # Only a secure hash is stored.
    # --------------------------------------------------

    password_hash = generate_password_hash(
        date_of_birth_normalized
    )


    # --------------------------------------------------
    # CREATE USER
    # --------------------------------------------------

    try:

        user_response = (
            supabase
            .table("users")
            .insert({
                "name":
                    name,

                "date_of_birth":
                    date_of_birth_normalized,

                "college_name":
                    college_name,

                "email":
                    email,

                "password_hash":
                    password_hash,

                "email_verified":
                    True,

                "is_logged_in":
                    False
            })
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not create user"
        )

        return jsonify({
            "error":
                "Could not create account. Please try again."
        }), 500


    # --------------------------------------------------
    # SUCCESS
    # --------------------------------------------------

    return jsonify({
        "message":
            "Registration successful! Your email has been verified.",
        "email":
            email
    }), 200


# ==================================================
# PASSWORD LOGIN
# ==================================================

@app.route(
    "/login-password",
    methods=["POST"]
)
def login_password():

    # --------------------------------------------------
    # GET REQUEST DATA
    # --------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    email = data.get(
        "email",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    ).strip()

    # Convert DD-MM-YYYY entered by the user
    # into YYYY-MM-DD used by the stored password.
    password_normalized = normalize_dob(
        password
    )


    # --------------------------------------------------
    # VALIDATE EMAIL
    # --------------------------------------------------

    if not is_valid_email(email):

        return jsonify({
            "error":
                "Please enter a valid email address."
        }), 400


    # --------------------------------------------------
    # VALIDATE PASSWORD
    # --------------------------------------------------

    if not password:

        return jsonify({
            "error":
                "Please enter your password."
        }), 400


    # --------------------------------------------------
    # FIND USER
    # --------------------------------------------------

    try:

        response = (
            supabase
            .table("users")
            .select(
                "id, name, email, password_hash, email_verified"
            )
            .eq(
                "email",
                email.lower()
            )
            .limit(1)
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not find user"
        )

        return jsonify({
            "error":
                "Could not check account. Please try again."
        }), 500


    # --------------------------------------------------
    # USER DOES NOT EXIST
    # --------------------------------------------------

    if not response.data:

        return jsonify({
            "error":
                "No account found with this email. Please register first."
        }), 404


    user = response.data[0]


    # --------------------------------------------------
    # EMAIL VERIFICATION
    # --------------------------------------------------

    if not user.get(
        "email_verified",
        False
    ):

        return jsonify({
            "error":
                "Please verify your email before logging in."
        }), 403


    # --------------------------------------------------
    # CHECK PASSWORD
    # --------------------------------------------------

    password_is_correct = check_password_hash(
        user["password_hash"],
        password_normalized or password
    )

    if not password_is_correct:

        return jsonify({
            "error":
                "Incorrect password."
        }), 401


    # --------------------------------------------------
    # CREATE SESSION
    # --------------------------------------------------

    create_login_session(
        user
    )


    # --------------------------------------------------
    # UPDATE DATABASE LOGIN STATUS
    # --------------------------------------------------

    try:

        update_user_login_status(
            user["id"]
        )

    except Exception:

        app.logger.exception(
            "Could not update login status"
        )

        session.clear()

        return jsonify({
            "error":
                "Could not complete login. Please try again."
        }), 500


    # --------------------------------------------------
    # SUCCESS
    # --------------------------------------------------

    return jsonify({
        "message":
            "Login successful!",

        "email":
            user["email"],

        "name":
            user["name"]
    }), 200


# ==================================================
# SEND LOGIN OTP
# ==================================================

@app.route(
    "/send-otp",
    methods=["POST"]
)
def send_otp():

    # --------------------------------------------------
    # CHECK GMAIL CONFIGURATION
    # --------------------------------------------------

    if not GMAIL_ADDRESS or not GMAIL_APP_PASSWORD:

        return jsonify({
            "error":
                "Gmail configuration is missing."
        }), 500


    # --------------------------------------------------
    # GET REQUEST DATA
    # --------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}

    email = data.get(
        "email",
        ""
    ).strip().lower()


    # --------------------------------------------------
    # VALIDATE EMAIL
    # --------------------------------------------------

    if not is_valid_email(email):

        return jsonify({
            "error":
                "Please enter a valid email address."
        }), 400


    # --------------------------------------------------
    # CHECK USER EXISTS
    # --------------------------------------------------

    try:

        user_response = (
            supabase
            .table("users")
            .select(
                "id, email, email_verified"
            )
            .eq(
                "email",
                email
            )
            .limit(1)
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not check user for OTP login"
        )

        return jsonify({
            "error":
                "Could not check account. Please try again."
        }), 500


    if not user_response.data:

        return jsonify({
            "error":
                "No account found with this email. Please register first."
        }), 404


    user = user_response.data[0]


    if not user.get(
        "email_verified",
        False
    ):

        return jsonify({
            "error":
                "Please verify your email before requesting a login OTP."
        }), 403


    # --------------------------------------------------
    # CHECK PREVIOUS OTP
    # --------------------------------------------------

    try:

        previous = get_latest_active_otp(
            email,
            "login"
        )

    except Exception:

        app.logger.exception(
            "Could not check previous OTP"
        )

        return jsonify({
            "error":
                "Could not check OTP status. Please try again."
        }), 500


    # --------------------------------------------------
    # RESEND WAIT CHECK
    # --------------------------------------------------

    if previous:

        previous_time = parse_supabase_datetime(
            previous["created_at"]
        )

        seconds_since_last = (
            utc_now() - previous_time
        ).total_seconds()

        if seconds_since_last < RESEND_WAIT_SECONDS:

            remaining = max(
                1,
                int(
                    RESEND_WAIT_SECONDS
                    - seconds_since_last
                )
            )

            return jsonify({
                "error":
                    f"Please wait {remaining} seconds before requesting another OTP."
            }), 429


    # --------------------------------------------------
    # GENERATE OTP
    # --------------------------------------------------

    otp = generate_otp()


    # --------------------------------------------------
    # HASH OTP
    # --------------------------------------------------

    otp_hash = generate_password_hash(
        otp
    )


    # --------------------------------------------------
    # EXPIRATION
    # --------------------------------------------------

    expires_at = (
        utc_now()
        + timedelta(
            seconds=OTP_EXPIRY_SECONDS
        )
    )


    # --------------------------------------------------
    # SAVE OTP
    # --------------------------------------------------

    try:

        insert_response = (
            supabase
            .table("otp_verifications")
            .insert({
                "email": email,
                "otp_hash": otp_hash,
                "purpose": "login",
                "expires_at": expires_at.isoformat(),
                "attempts": 0
            })
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Supabase OTP insert failed"
        )

        return jsonify({
            "error":
                "Could not create OTP. Please try again."
        }), 500


    # --------------------------------------------------
    # SEND OTP EMAIL
    # --------------------------------------------------

    try:

        send_otp_email(
            email,
            otp
        )

    except Exception:

        app.logger.exception(
            "Gmail sending failed"
        )

        # Disable OTP if Gmail failed
        try:

            if insert_response.data:

                otp_id = insert_response.data[0]["id"]

                consume_otp(
                    otp_id
                )

        except Exception:

            app.logger.exception(
                "Could not disable failed OTP"
            )

        return jsonify({
            "error":
                "Could not send email. Check Gmail configuration."
        }), 502


    # --------------------------------------------------
    # SUCCESS
    # --------------------------------------------------

    return jsonify({
        "message":
            "OTP sent! Check your email inbox."
    }), 200


# ==================================================
# VERIFY LOGIN OTP
# ==================================================

@app.route(
    "/verify-otp",
    methods=["POST"]
)
def verify_otp():

    # --------------------------------------------------
    # GET REQUEST DATA
    # --------------------------------------------------

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


    # --------------------------------------------------
    # VALIDATE EMAIL
    # --------------------------------------------------

    if not is_valid_email(email):

        return jsonify({
            "error":
                "Please enter a valid email address."
        }), 400


    # --------------------------------------------------
    # VALIDATE OTP
    # --------------------------------------------------

    if not re.fullmatch(
        r"\d{6}",
        entered_otp
    ):

        return jsonify({
            "error":
                "OTP must contain exactly 6 digits."
        }), 400


    # --------------------------------------------------
    # FIND USER
    # --------------------------------------------------

    try:

        user_response = (
            supabase
            .table("users")
            .select(
                "id, name, email, email_verified"
            )
            .eq(
                "email",
                email
            )
            .limit(1)
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not find user for OTP login"
        )

        return jsonify({
            "error":
                "Could not check account. Please try again."
        }), 500


    # --------------------------------------------------
    # USER DOES NOT EXIST
    # --------------------------------------------------

    if not user_response.data:

        return jsonify({
            "error":
                "No account found with this email. Please register first."
        }), 404


    user = user_response.data[0]


    # --------------------------------------------------
    # EMAIL MUST BE VERIFIED
    # --------------------------------------------------

    if not user.get(
        "email_verified",
        False
    ):

        return jsonify({
            "error":
                "Please verify your email before logging in."
        }), 403


    # --------------------------------------------------
    # FIND ACTIVE LOGIN OTP
    # --------------------------------------------------

    try:

        record = get_latest_active_otp(
            email,
            "login"
        )

    except Exception:

        app.logger.exception(
            "Could not retrieve login OTP"
        )

        return jsonify({
            "error":
                "Could not retrieve OTP. Please try again."
        }), 500


    # --------------------------------------------------
    # NO OTP
    # --------------------------------------------------

    if not record:

        return jsonify({
            "error":
                "No active OTP. Please request a new OTP."
        }), 400


    # --------------------------------------------------
    # CHECK EXPIRATION
    # --------------------------------------------------

    expires_at = parse_supabase_datetime(
        record["expires_at"]
    )

    if utc_now() >= expires_at:

        try:

            consume_otp(
                record["id"]
            )

        except Exception:

            app.logger.exception(
                "Could not mark expired OTP"
            )

        return jsonify({
            "error":
                "OTP expired. Please request a new OTP."
        }), 400


    # --------------------------------------------------
    # CHECK ATTEMPTS
    # --------------------------------------------------

    attempts = record.get(
        "attempts",
        0
    )

    if attempts >= MAX_ATTEMPTS:

        try:

            consume_otp(
                record["id"]
            )

        except Exception:

            app.logger.exception(
                "Could not disable OTP"
            )

        return jsonify({
            "error":
                "Too many attempts. Request a new OTP."
        }), 429


    # --------------------------------------------------
    # INCREASE ATTEMPT COUNT
    # --------------------------------------------------

    new_attempt_count = attempts + 1

    try:

        (
            supabase
            .table("otp_verifications")
            .update({
                "attempts":
                    new_attempt_count
            })
            .eq(
                "id",
                record["id"]
            )
            .execute()
        )

    except Exception:

        app.logger.exception(
            "Could not update OTP attempts"
        )

        return jsonify({
            "error":
                "Could not verify OTP. Please try again."
        }), 500


    # --------------------------------------------------
    # CHECK OTP
    # --------------------------------------------------

    otp_is_correct = check_password_hash(
        record["otp_hash"],
        entered_otp
    )


    if not otp_is_correct:

        if new_attempt_count >= MAX_ATTEMPTS:

            try:

                consume_otp(
                    record["id"]
                )

            except Exception:

                app.logger.exception(
                    "Could not disable OTP"
                )

            return jsonify({
                "error":
                    "Too many attempts. Request a new OTP."
            }), 429

        return jsonify({
            "error":
                "Incorrect OTP."
        }), 400


    # --------------------------------------------------
    # OTP CORRECT
    # --------------------------------------------------

    try:

        consume_otp(
            record["id"]
        )

    except Exception:

        app.logger.exception(
            "Could not consume OTP"
        )

        return jsonify({
            "error":
                "Could not complete login. Please try again."
        }), 500


    # --------------------------------------------------
    # CREATE LOGIN SESSION
    # --------------------------------------------------

    create_login_session(
        user
    )


    # --------------------------------------------------
    # UPDATE DATABASE LOGIN STATUS
    # --------------------------------------------------

    try:

        update_user_login_status(
            user["id"]
        )

    except Exception:

        app.logger.exception(
            "Could not update OTP login status"
        )

        session.clear()

        return jsonify({
            "error":
                "Could not complete login. Please try again."
        }), 500


    # --------------------------------------------------
    # SUCCESS
    # --------------------------------------------------

    return jsonify({
        "message":
            "Login successful!",

        "email":
            user["email"],

        "name":
            user["name"]
    }), 200


# ==================================================
# CHECK LOGIN STATUS
# ==================================================

@app.route("/me")
def me():

    # --------------------------------------------------
    # CHECK SESSION
    # --------------------------------------------------

    if "user_id" not in session:

        return jsonify({
            "logged_in":
                False
        }), 401


    # --------------------------------------------------
    # RETURN USER SESSION
    # --------------------------------------------------

    return jsonify({
        "logged_in":
            True,

        "user_id":
            session["user_id"],

        "email":
            session["email"],

        "name":
            session.get(
                "name",
                "User"
            )
    }), 200


# ==================================================
# LOGOUT
# ==================================================

@app.route(
    "/logout",
    methods=["POST"]
)
def logout():

    # --------------------------------------------------
    # GET CURRENT USER
    # --------------------------------------------------

    user_id = session.get(
        "user_id"
    )


    # --------------------------------------------------
    # UPDATE DATABASE
    # --------------------------------------------------

    if user_id:

        try:

            (
                supabase
                .table("users")
                .update({
                    "is_logged_in":
                        False,

                    "last_logout_at":
                        utc_now().isoformat()
                })
                .eq(
                    "id",
                    user_id
                )
                .execute()
            )

        except Exception:

            app.logger.exception(
                "Could not update logout status"
            )

            return jsonify({
                "error":
                    "Could not complete logout. Please try again."
            }), 500


    # --------------------------------------------------
    # CLEAR FLASK SESSION
    # --------------------------------------------------

    session.clear()


    # --------------------------------------------------
    # SUCCESS
    # --------------------------------------------------

    return jsonify({
        "message":
            "Logged out successfully."
    }), 200


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return jsonify({
            "error":
                "Login required."
        }), 401

    return render_template(
        "dashboard.html"
    )


# ==================================================
# ADMIN SETTINGS
# ==================================================

# By default, the Gmail sender account is the admin account.
# You can override this with the ADMIN_EMAIL environment variable.

ADMIN_EMAIL = os.environ.get(
    "ADMIN_EMAIL",
    GMAIL_ADDRESS or ""
).strip().lower()


def admin_allowed():

    return (
        bool(ADMIN_EMAIL)
        and "user_id" in session
        and session.get(
            "email",
            ""
        ).strip().lower() == ADMIN_EMAIL
    )


# ==================================================
# ADMIN PAGE
# ==================================================

@app.route("/admin")
def admin_page():

    if not admin_allowed():

        return jsonify({
            "error":
                "Admin access required."
        }), 403

    return render_template(
        "admin.html"
    )


# ==================================================
# ADMIN - VIEW USERS
# ==================================================

@app.route(
    "/admin/users",
    methods=["GET"]
)
def admin_users():

    if not admin_allowed():

        return jsonify({
            "error":
                "Admin access required."
        }), 403

    try:

        response = (
            supabase
            .table("users")
            .select(
                "id, name, date_of_birth, college_name, email, "
                "email_verified, is_logged_in, created_at, "
                "last_login_at, last_logout_at"
            )
            .order(
                "created_at",
                desc=True
            )
            .execute()
        )

        return jsonify({
            "users":
                response.data or []
        }), 200

    except Exception:

        app.logger.exception(
            "Could not load admin users"
        )

        return jsonify({
            "error":
                "Could not load users. Please try again."
        }), 500


# ==================================================
# ADMIN - EDIT USER
# ==================================================

@app.route(
    "/admin/users/<int:user_id>",
    methods=["PATCH"]
)
def admin_update_user(user_id):

    if not admin_allowed():

        return jsonify({
            "error":
                "Admin access required."
        }), 403


    data = request.get_json(
        silent=True
    ) or {}


    allowed_fields = {
        "name",
        "date_of_birth",
        "college_name",
        "email",
        "email_verified"
    }


    updates = {
        key: data[key]
        for key in allowed_fields
        if key in data
    }


    if not updates:

        return jsonify({
            "error":
                "No editable fields were provided."
        }), 400


    # --------------------------------------------------
    # NAME
    # --------------------------------------------------

    if "name" in updates:

        updates["name"] = str(
            updates["name"]
        ).strip()

        if not updates["name"]:

            return jsonify({
                "error":
                    "Name is required."
            }), 400


    # --------------------------------------------------
    # DATE OF BIRTH
    # --------------------------------------------------

    if "date_of_birth" in updates:

        updates["date_of_birth"] = str(
            updates["date_of_birth"]
        ).strip()

        # Accept DD-MM-YYYY from admin
        normalized_admin_dob = normalize_dob(
            updates["date_of_birth"]
        )

        # Also allow existing database YYYY-MM-DD
        # format for compatibility.
        if normalized_admin_dob:

            updates["date_of_birth"] = (
                normalized_admin_dob
            )

        else:

            try:

                datetime.strptime(
                    updates["date_of_birth"],
                    "%Y-%m-%d"
                )

            except ValueError:

                return jsonify({
                    "error":
                        "Date of birth must use DD-MM-YYYY format."
                }), 400


    # --------------------------------------------------
    # COLLEGE
    # --------------------------------------------------

    if "college_name" in updates:

        updates["college_name"] = str(
            updates["college_name"]
        ).strip()

        if not updates["college_name"]:

            return jsonify({
                "error":
                    "College name is required."
            }), 400


    # --------------------------------------------------
    # EMAIL
    # --------------------------------------------------

    if "email" in updates:

        updates["email"] = str(
            updates["email"]
        ).strip().lower()

        if not is_valid_email(
            updates["email"]
        ):

            return jsonify({
                "error":
                    "Please enter a valid email address."
            }), 400


    # --------------------------------------------------
    # EMAIL VERIFIED
    # --------------------------------------------------

    if "email_verified" in updates:

        if not isinstance(
            updates["email_verified"],
            bool
        ):

            return jsonify({
                "error":
                    "email_verified must be true or false."
            }), 400


    # --------------------------------------------------
    # PROTECT ADMIN EMAIL
    # --------------------------------------------------

    if (
        user_id == session.get("user_id")
        and "email" in updates
        and updates["email"] != ADMIN_EMAIL
    ):

        return jsonify({
            "error":
                "You cannot change the email of the current admin account."
        }), 400


    # --------------------------------------------------
    # UPDATE USER
    # --------------------------------------------------

    try:

        response = (
            supabase
            .table("users")
            .update(updates)
            .eq(
                "id",
                user_id
            )
            .execute()
        )


        if not response.data:

            return jsonify({
                "error":
                    "User not found."
            }), 404


        # Keep current Flask session synchronized
        if user_id == session.get(
            "user_id"
        ):

            if "name" in updates:

                session["name"] = updates["name"]

            if "email" in updates:

                session["email"] = updates["email"]


        return jsonify({
            "message":
                "User updated successfully.",

            "user":
                response.data[0]
        }), 200


    except Exception as exc:

        error_text = str(exc).lower()

        if (
            "duplicate" in error_text
            or "unique" in error_text
        ):

            return jsonify({
                "error":
                    "That email address is already registered."
            }), 409


        app.logger.exception(
            "Could not update admin user"
        )

        return jsonify({
            "error":
                "Could not update user. Please try again."
        }), 500


# ==================================================
# ADMIN - DELETE USER
# ==================================================

@app.route(
    "/admin/users/<int:user_id>",
    methods=["DELETE"]
)
def admin_delete_user(user_id):

    if not admin_allowed():

        return jsonify({
            "error":
                "Admin access required."
        }), 403


    # Never allow admin to delete own account
    if user_id == session.get(
        "user_id"
    ):

        return jsonify({
            "error":
                "You cannot delete the currently logged-in admin account."
        }), 400


    try:

        response = (
            supabase
            .table("users")
            .delete()
            .eq(
                "id",
                user_id
            )
            .execute()
        )


        if not response.data:

            return jsonify({
                "error":
                    "User not found."
            }), 404


        return jsonify({
            "message":
                "User deleted successfully."
        }), 200


    except Exception:

        app.logger.exception(
            "Could not delete admin user"
        )

        return jsonify({
            "error":
                "Could not delete user. Please try again."
        }), 500


# ==================================================
# SESSION COOKIE SETTINGS
# ==================================================

app.config.update({

    "SESSION_COOKIE_HTTPONLY":
        True,

    "SESSION_COOKIE_SAMESITE":
        "Lax",

    # Local development uses HTTP.
    # Change to True for HTTPS production if needed.
    "SESSION_COOKIE_SECURE":
        False
})


# ==================================================
# START SERVER
# ==================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )