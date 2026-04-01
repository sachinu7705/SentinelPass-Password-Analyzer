import os
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"
from flask import flash
from ml_model import predict_strength
from flask import Flask, render_template, request, jsonify
import re
import math
import hashlib
import requests
import secrets
import string
import smtplib
import random
import csv
from io import StringIO
from flask import Response
from dotenv import load_dotenv
from flask import redirect, url_for
from email.mime.text import MIMEText
from flask import session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from datetime import datetime
from datetime import timedelta


app = Flask(__name__)

load_dotenv()

# ============================================
# EMAIL CONFIGURATION
# ============================================
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_DEFAULT_SENDER'] = MAIL_USERNAME

# ============================================
# DATABASE CONFIGURATION
# ============================================
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ============================================
# FLASK CONFIGURATION
# ============================================
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

app.permanent_session_lifetime = timedelta(days=7)

# Debug prints
print(f"Email configured for: {MAIL_USERNAME}")
print(f"Password set: {'✅ Yes' if MAIL_PASSWORD else '❌ No'}")
print(f"Password length: {len(MAIL_PASSWORD) if MAIL_PASSWORD else 0}")
print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# ============================================
# OAUTH CONFIGURATION
# ============================================
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

db = SQLAlchemy(app)
from flask_migrate import Migrate
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ... rest of your code (User class, routes, etc.) ...


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(150), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=True)

    auth_provider = db.Column(db.String(50), default="local")

from datetime import datetime

class PasswordHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(100))
    category = db.Column(db.String(50))
    password = db.Column(db.String(255))
    entropy = db.Column(db.Float)
    crack_time = db.Column(db.Float)
    ai_score = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

# Load common passwords
with open("common_passwords.txt", "r") as f:
    common_passwords = set(f.read().splitlines())

def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): charset += 32
    if charset == 0: return 0
    return round(len(password) * math.log2(charset), 2)

def estimate_crack_time(entropy):
    guesses_per_sec = 1e9
    seconds = 2 ** entropy / guesses_per_sec
    return seconds

def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    hashes = response.text.splitlines()

    for line in hashes:
        h, count = line.split(":")
        if h == suffix:
            return True
    return False

def generate_password(length=14):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def send_otp_email(receiver_email, otp):
    """Send OTP email with proper configuration"""
    try:
        print(f"Attempting to send OTP to: {receiver_email}")
        print(f"Generated OTP: {otp}")
        
        # Get email config from app.config
        sender_email = app.config.get('MAIL_USERNAME')
        sender_password = app.config.get('MAIL_PASSWORD')
        
        print(f"Using sender email: {sender_email}")
        
        if not sender_email or not sender_password:
            print("❌ Email credentials not configured!")
            return False
        
        # Create HTML email
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;">
            <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 5px 20px rgba(0,0,0,0.1);">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">🔐 SentinelPass</h1>
                    <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0;">Password Security Analyzer</p>
                </div>
                <div style="padding: 30px;">
                    <h2 style="color: #333; margin-top: 0;">Email Verification</h2>
                    <p style="color: #666; line-height: 1.6;">Hello,</p>
                    <p style="color: #666; line-height: 1.6;">Thank you for registering with SentinelPass. Please use the following verification code to complete your registration:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-size: 36px; font-weight: bold; padding: 20px 30px; border-radius: 10px; display: inline-block; letter-spacing: 8px; font-family: monospace;">
                            {otp}
                        </div>
                    </div>
                    <p style="color: #666; font-size: 14px;">This code will expire in <strong>5 minutes</strong>.</p>
                    <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
                    <hr style="margin: 25px 0; border: none; border-top: 1px solid #eee;">
                    <p style="color: #999; font-size: 12px; text-align: center; margin: 0;">SentinelPass - Making passwords secure, one analysis at a time</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create email message
        msg = MIMEText(html_content, "html")
        msg["Subject"] = "🔐 SentinelPass - Your OTP Verification Code"
        msg["From"] = f"SentinelPass <{sender_email}>"
        msg["To"] = receiver_email
        
        # Send email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.set_debuglevel(0)  # Set to 1 for debugging
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        print("✅ OTP SENT SUCCESSFULLY!")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ EMAIL AUTHENTICATION ERROR: {e}")
        print("Please check:")
        print("1. Email address is correct")
        print("2. App Password is correct (if using 2FA)")
        print("3. Less secure app access is enabled (if no 2FA)")
        return False
    except Exception as e:
        print(f"❌ EMAIL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login/google")
def login_google():
    redirect_uri = url_for("google_callback", _external=True)
    print(f"Redirect URI being used: {redirect_uri}")  # Add this line
    return google.authorize_redirect(
        redirect_uri,
        prompt="select_account"
    )

@app.route("/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()

        user_info = token.get("userinfo")

        if not user_info:
            resp = google.get("https://openidconnect.googleapis.com/v1/userinfo")
            user_info = resp.json()

        email = user_info.get("email")

        if not email:
            print("OAuth Error: No email provided by Google.")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()

        if not user:
            user = User(
                email=email,
                auth_provider="google"
            )
            db.session.add(user)
            db.session.commit()

        login_user(user)

        return redirect(url_for("dashboard"))

    except Exception as e:
        print("Google Auth Error:", e)
        return redirect(url_for("login"))


@app.route("/check", methods=["POST"])
def check():

    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({"error": "No password"}), 400

    password = data.get("password")

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    breached = check_breach(password)
    is_common = password in common_passwords
    ml_score = predict_strength(password)

    # ❌ NO DATABASE SAVE HERE

    return jsonify({
        "entropy": entropy,
        "crack_time_seconds": crack_time,
        "breached": breached,
        "common": is_common,
        "ml_score": ml_score
    })

@app.route("/generate")
def generate():
    pwd = generate_password()
    return jsonify({"password": pwd})

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        action = request.form.get("action")
        print("ACTION RECEIVED:", action)

        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if action == "send_otp":

            otp = str(random.randint(100000, 999999))
            session["otp"] = otp
            session["temp_email"] = email
            session["temp_password"] = password

            print("Generated OTP:", otp)

            send_otp_email(email, otp)

            return "", 200   # IMPORTANT for fetch()

        if action == "verify":

            user_otp = request.form.get("otp")

            if user_otp == session.get("otp"):

                hashed_password = generate_password_hash(
                    session.get("temp_password"))

                new_user = User(
                    email=session.get("temp_email"),
                    password=hashed_password,
                    auth_provider="local"
                )

                db.session.add(new_user)
                db.session.commit()

                session.clear()

                return redirect(url_for("login"))

            else:
                return "", 400

    return render_template("register.html")

#login

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and user.auth_provider == "google":
            return render_template("login.html",
                error="Please login using Google for this account.")


        if user and user.auth_provider == "local" and check_password_hash(user.password, password):

            login_user(user)  # 🔥 VERY IMPORTANT

            return redirect(url_for("dashboard"))  # 🔥 REDIRECT HERE

        else:
            return render_template("login.html",
                                   error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/verify-otp", methods=["POST"])
def verify_otp_endpoint():
    """Verify OTP and complete registration"""
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        otp = data.get("otp")
        
        # Check if OTP exists and matches
        stored_otp = session.get("otp")
        stored_email = session.get("temp_email")
        stored_password = session.get("temp_password")
        expiry = session.get("otp_expiry", 0)
        
        # Check expiry
        if datetime.now().timestamp() > expiry:
            return jsonify({"success": False, "message": "OTP expired. Please request a new one."}), 400
        
        if not stored_otp or not stored_email:
            return jsonify({"success": False, "message": "No OTP request found. Please start over."}), 400
        
        if otp != stored_otp:
            return jsonify({"success": False, "message": "Invalid OTP. Please try again."}), 400
        
        if email != stored_email:
            return jsonify({"success": False, "message": "Email mismatch. Please start over."}), 400
        
        # Create user account
        hashed_password = generate_password_hash(password)
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"success": False, "message": "Email already registered. Please login."}), 400
        
        new_user = User(
            email=email,
            password=hashed_password,
            auth_provider="local"
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Clear session data
        session.pop("otp", None)
        session.pop("temp_email", None)
        session.pop("temp_password", None)
        session.pop("otp_expiry", None)
        
        return jsonify({"success": True, "message": "Registration successful!"})
        
    except Exception as e:
        print(f"Verify OTP error: {e}")
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route("/resend-otp", methods=["POST"])
def resend_otp_endpoint():
    """Resend OTP"""
    try:
        data = request.get_json()
        email = data.get("email")
        
        if not email:
            return jsonify({"success": False, "message": "Email required"}), 400
        
        # Generate new OTP
        otp = str(random.randint(100000, 999999))
        
        # Update session
        session["otp"] = otp
        session["otp_expiry"] = datetime.now().timestamp() + 300
        
        print(f"Resending OTP to {email}: {otp}")
        
        # Send OTP email
        send_otp_email(email, otp)
        
        return jsonify({"success": True, "message": "OTP resent successfully"})
        
    except Exception as e:
        print(f"Resend OTP error: {e}")
        return jsonify({"success": False, "message": "Failed to resend OTP"}), 500


@app.route("/send-otp", methods=["POST"])
def send_otp_endpoint():
    """Send OTP to email for registration"""
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        
        if not email or not password:
            return jsonify({"success": False, "message": "Email and password required"}), 400
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"success": False, "message": "Email already registered. Please login."}), 400
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        
        # Store in session
        session["otp"] = otp
        session["temp_email"] = email
        session["temp_password"] = password
        session["otp_expiry"] = datetime.now().timestamp() + 300  # 5 minutes expiry
        
        print(f"Generated OTP for {email}: {otp}")
        
        # Send OTP email
        email_sent = send_otp_email(email, otp)
        
        if email_sent:
            return jsonify({"success": True, "message": "OTP sent successfully to your email"})
        else:
            return jsonify({"success": False, "message": "Failed to send email. Please check your email address and try again."}), 500
            
    except Exception as e:
        print(f"Send OTP error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error. Please try again."}), 500
    

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():

    entropy = None
    crack_time = None
    ai_score = None
    entropy_label = None
    entropy_color = None

    service_name = ""
    category = ""
    password = ""

    if request.method == "POST":

        service_name = request.form.get("service_name")
        category = request.form.get("category")
        password = request.form.get("password")

        if password:

            entropy = calculate_entropy(password)
            crack_time = estimate_crack_time(entropy)
            ai_score = predict_strength(password)

            # 🔥 Convert entropy number to label
            if entropy < 30:
                entropy_label = "Very Weak"
                entropy_color = "red"
            elif entropy < 50:
                entropy_label = "Weak"
                entropy_color = "orange"
            elif entropy < 70:
                entropy_label = "Good"
                entropy_color = "#3b82f6"
            elif entropy < 90:
                entropy_label = "Better"
                entropy_color = "#10b981"
            else:
                entropy_label = "Very Strong"
                entropy_color = "darkgreen"

            if request.method == "POST":

                action = request.form.get("action")

                service_name = request.form.get("service_name")
                category = request.form.get("category")
                password = request.form.get("password")

                if password:

                    entropy = calculate_entropy(password)
                    crack_time = estimate_crack_time(entropy)
                    ai_score = predict_strength(password)

                # SAVE PASSWORD
                if action == "save":

                    new_entry = PasswordHistory(
                        service_name=service_name,
                        category=category,
                        password=password,
                        entropy=entropy,
                        crack_time=crack_time,
                        ai_score=ai_score,
                        user_id=current_user.id
                    )

                    db.session.add(new_entry)
                    db.session.commit()

                    return redirect(url_for("dashboard"))
            

    history = PasswordHistory.query.filter_by(
        user_id=current_user.id
    ).all()

    return render_template(
        "dashboard.html",
        email=current_user.email,
        entropy=entropy,
        entropy_label=entropy_label,
        entropy_color=entropy_color,
        crack_time=crack_time,
        ai_score=ai_score,
        service_name=service_name,
        category=category,
        password=password,
        history=history
    )



@app.route("/analyzer")
@login_required
def analyzer():
    return render_template("index.html")


@app.route("/export")
@login_required
def export_csv():

    history = PasswordHistory.query.filter_by(
        user_id=current_user.id
    ).all()

    def generate():
        yield "Service,Category,Entropy,AI Score\n"
        for item in history:
            yield f"{item.service_name},{item.category},{item.entropy},{item.ai_score}\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=history.csv"}
    )



@app.route("/save-password", methods=["POST"])
@login_required
def save_password():

    data = request.get_json()

    password = data.get("password")
    service_name = data.get("service_name")

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    ai_score = predict_strength(password)

    new_entry = PasswordHistory(
        password=password,
        service_name=service_name,
        entropy=entropy,
        crack_time=crack_time,
        ai_score=ai_score,
        user_id=current_user.id
    )

    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"message": "Saved successfully"})


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", email=current_user.email)

@app.route("/delete/<int:id>")
@login_required
def delete_entry(id):

    entry = PasswordHistory.query.get_or_404(id)

    if entry.user_id != current_user.id:
        return "Unauthorized", 403

    db.session.delete(entry)
    db.session.commit()

    return redirect(url_for("dashboard"))


@app.route("/edit/<int:id>", methods=["POST"])
@login_required
def edit_password(id):

    entry = PasswordHistory.query.get_or_404(id)

    entry.service_name = request.form.get("service_name")
    entry.category = request.form.get("category")
    entry.password = request.form.get("password")

    db.session.commit()

    return redirect(url_for("dashboard"))

@app.route("/delete-all")
@login_required
def delete_all():

    PasswordHistory.query.filter_by(
        user_id=current_user.id
    ).delete()

    db.session.commit()

    return redirect(url_for("dashboard"))
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    
    if request.method == "POST":
        try:
            data = request.get_json()
            email = data.get("email")
            
            print(f"🔍 Looking for user: {email}")
            
            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({"success": False, "message": "Email not found. Please check and try again."}), 404
            
            # Generate OTP
            otp = str(random.randint(100000, 999999))
            print(f"🔑 Generated reset OTP: {otp}")
            
            # Store in session
            session["reset_otp"] = otp
            session["reset_email"] = email
            session["reset_expiry"] = datetime.now().timestamp() + 300
            
            # Send OTP email
            email_sent = send_reset_otp_email(email, otp)
            
            if email_sent:
                return jsonify({"success": True, "message": "Reset code sent to your email"})
            else:
                return jsonify({"success": False, "message": "Failed to send email. Please try again later."}), 500
                
        except Exception as e:
            print(f"Forgot password error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "message": "Server error. Please try again."}), 500

@app.route("/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")
    
    if datetime.now().timestamp() > session.get("reset_expiry", 0):
        return jsonify({"success": False, "message": "OTP expired"})
    
    if otp == session.get("reset_otp") and email == session.get("reset_email"):
        return jsonify({"success": True})
    
    return jsonify({"success": False, "message": "Invalid OTP"})

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email")
    new_password = data.get("new_password")
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"})
    
    user.password = generate_password_hash(new_password)
    db.session.commit()
    
    # Clear reset session
    session.pop("reset_otp", None)
    session.pop("reset_email", None)
    session.pop("reset_expiry", None)
    
    return jsonify({"success": True, "message": "Password reset successful"})

def send_reset_otp_email(receiver_email, otp):
    """Send OTP for password reset"""
    try:
        # Get email config from app.config
        sender_email = app.config.get('MAIL_USERNAME')
        sender_password = app.config.get('MAIL_PASSWORD')
        
        if not sender_email or not sender_password:
            print("❌ Email credentials not configured in app.config!")
            print("Please check your .env file and app.config settings")
            return False
        
        print(f"📧 Sending reset OTP to: {receiver_email}")
        print(f"📧 From: {sender_email}")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;">
            <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 5px 20px rgba(0,0,0,0.1);">
                <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px;">🔐 SentinelPass</h1>
                    <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0;">Password Reset Request</p>
                </div>
                <div style="padding: 30px;">
                    <h2 style="color: #333; margin-top: 0;">Reset Your Password</h2>
                    <p style="color: #666; line-height: 1.6;">Hello,</p>
                    <p style="color: #666; line-height: 1.6;">We received a request to reset your password. Please use the following verification code:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; font-size: 36px; font-weight: bold; padding: 20px 30px; border-radius: 10px; display: inline-block; letter-spacing: 8px; font-family: monospace;">
                            {otp}
                        </div>
                    </div>
                    <p style="color: #666; font-size: 14px;">This code will expire in <strong>5 minutes</strong>.</p>
                    <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
                    <hr style="margin: 25px 0; border: none; border-top: 1px solid #eee;">
                    <p style="color: #999; font-size: 12px; text-align: center; margin: 0;">SentinelPass - Password Security Analyzer</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEText(html_content, "html")
        msg["Subject"] = "🔐 SentinelPass - Password Reset OTP"
        msg["From"] = f"SentinelPass <{sender_email}>"
        msg["To"] = receiver_email
        
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.set_debuglevel(0)  # Set to 1 for debugging
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        print("✅ Reset OTP sent successfully!")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ EMAIL AUTHENTICATION ERROR: {e}")
        print("\nSOLUTIONS:")
        print("1. If you have 2FA enabled, you MUST use an App Password:")
        print("   - Go to: https://myaccount.google.com/apppasswords")
        print("   - Generate a new app password for 'Mail'")
        print("   - Update MAIL_PASSWORD in .env with the 16-character code")
        print("\n2. If you don't have 2FA, enable 'Less secure app access':")
        print("   - Go to: https://myaccount.google.com/lesssecureapps")
        print("   - Turn ON 'Allow less secure apps'")
        return False
    except Exception as e:
        print(f"❌ EMAIL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False



with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
