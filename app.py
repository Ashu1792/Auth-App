from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import bcrypt
import re
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

db = SQLAlchemy(app)

# ================= MODEL =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

# ================= LOGIN REQUIRED DECORATOR =================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first!", "warning")
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


# ================= ROUTES =================

@app.route("/")
def home():
    return render_template("index.html")


# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # ====== VALIDATION ======
        if not name:
            flash("Name should not be empty!", "danger")
            return redirect("/register")

        if not email:
            flash("Email should not be empty!", "danger")
            return redirect("/register")

        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern, email):
            flash("Invalid email format!", "danger")
            return redirect("/register")

        if not password:
            flash("Password should not be empty!", "danger")
            return redirect("/register")

        if len(password) < 6:
            flash("Password must be at least 6 characters!", "danger")
            return redirect("/register")

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered!", "danger")
            return redirect("/register")

        # ====== SAVE USER ======
        new_user = User(name, email, password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect("/login")

    return render_template("register.html")


# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and Password are required!", "danger")
            return redirect("/login")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            session["user_name"] = user.name
            flash("Login successful!", "success")
            return redirect("/dashboard")
        else:
            flash("Invalid email or password!", "danger")
            return redirect("/login")

    return render_template("login.html")


# ================= DASHBOARD =================
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=session["user_name"])


# ================= LOGOUT =================
@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)