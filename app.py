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



GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
 

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

app.permanent_session_lifetime = timedelta(days=7)


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
    try:
        print("Attempting to send OTP to:", receiver_email)
        print("Generated OTP:", otp)

        msg = MIMEText(f"Your OTP is: {otp}")
        msg["Subject"] = "SentinelPass OTP Verification"
        msg["From"] = app.config["MAIL_EMAIL"]
        msg["To"] = receiver_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(app.config["MAIL_EMAIL"], app.config["MAIL_PASSWORD"])
            server.send_message(msg)

        print("OTP SENT SUCCESSFULLY")

    except Exception as e:
        print("EMAIL ERROR:", e)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login/google")
def login_google():
    redirect_uri = url_for("google_callback", _external=True)
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

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        user_otp = request.form["otp"]

        if user_otp == session.get("otp"):
            email = session.get("temp_email")
            password = session.get("temp_password")

            hashed_password = generate_password_hash(password)

            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            session.pop("otp", None)
            session.pop("temp_email", None)
            session.pop("temp_password", None)

            return redirect(url_for("login"))

        return render_template("verify_otp.html", error="Invalid OTP")

    return render_template("verify_otp.html")


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




with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
