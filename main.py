import os

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    current_user,
)
from flask_login import logout_user
from werkzeug.security import generate_password_hash
import secrets
import warnings
import requests
import sqlite3

# Suppressing the warning
from werkzeug.utils import secure_filename

warnings.filterwarnings("ignore", category=DeprecationWarning)

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
UPLOAD_FOLDER_PROFILE = "static/uploads/profile-photo"

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["UPLOAD_FOLDER_PROFILE"] = UPLOAD_FOLDER_PROFILE
app.secret_key = secrets.token_hex(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"  # SQLite database

conn = sqlite3.connect("comments.db", check_same_thread=False)
c = conn.cursor()
c.execute(
    """CREATE TABLE IF NOT EXISTS comments
             (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, comment TEXT)"""
)
conn.commit()

db = SQLAlchemy(app)


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("photos", lazy=True))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_photo = db.Column(db.String(255))  # Add this line
    profile_photos = db.Column(db.String(1000))  # Store a list of filenames

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email
        self.profile_photo = None  # Set initial value to None
        self.profile_photos = ""  # Initialize the list as an empty string


db.create_all()  # Create database tables if they don't exist

login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            # Log in the user using login_user function
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html", error=None)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        new_password = request.form["password"]

        if (
                len(new_password) >= 6
                and any(char.isupper() for char in new_password)
                and any(char.isdigit() or char in "!@#$%^&*()_+" for char in new_password)
        ):
            current_user.name = name
            current_user.email = email
            current_user.password = generate_password_hash(
                new_password, method="sha256"
            )
            db.session.commit()
            flash("Profile has been updated.", "success")
        else:
            flash(
                "Password must be at least 6 characters long, contain at least one uppercase letter, and one digit or "
                "special symbol.",
                "error",
            )

        # Handle profile photo upload
        if "photo" in request.files:
            photo = request.files["photo"]
            if photo.filename != "":
                filename = secure_filename(photo.filename)
                photo_path = os.path.join(app.config["UPLOAD_FOLDER_PROFILE"], filename)
                photo.save(photo_path)  # Save the file to the 'uploads' folder
                current_user.profile_photo = (
                    filename  # Update the user's profile photo attribute
                )
                db.session.commit()

    return render_template(
        "profile.html", username=current_user.username, current_user=current_user
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hcaptcha_response = request.form.get("h-captcha-response")
        secret_key = "0xf391442b9432C94165DF28f7B88538b4aC2F983e"
        response = requests.post(
            "https://hcaptcha.com/siteverify",
            data={"secret": secret_key, "response": hcaptcha_response},
        )
        result = response.json()

        if not result.get("success"):
            return render_template(
                "register.html", error="hCaptcha verification failed"
            )

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()

        if existing_user:
            return render_template("register.html", error="Username already taken")
        elif existing_email:
            return render_template("register.html", error="Email already taken")

        # Password validation rules
        if (
                len(password) < 6
                or not any(char.isupper() for char in password)
                or not any(char.isdigit() or char in "!@#$%^&*()_+" for char in password)
        ):
            return render_template(
                "register.html",
                error="Password must be at least 6 characters long, contain at least one uppercase letter, "
                      "and one digit or special symbol.",
            )

        new_user = User(username=username, password=password, email=email)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html", error=None)


@app.route("/upload_photo", methods=["POST"])
@login_required
def upload_photo():
    if "photo" in request.files:
        photo = request.files["photo"]
        if photo.filename != "":
            filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            photo.save(photo_path)

            if current_user.profile_photos:
                current_user.profile_photos += "," + filename
            else:
                current_user.profile_photos = filename

            db.session.commit()
    return redirect(url_for("dashboard"))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/add_comment", methods=["POST"])
@login_required
def add_comment():
    comment = request.form["comment"]  # Get the comment from the form
    if comment.strip():  # Check if the comment is not empty or whitespace only
        c.execute(
            "INSERT INTO comments (name, comment) VALUES (?, ?)",
            (current_user.username, comment),
        )
        conn.commit()
    return redirect(url_for("dashboard"))  # Redirect to your dashboard route


@app.route("/like_photo/<filename>", methods=["POST"])
@login_required
def like_photo(filename):
    photo = Photo.query.filter_by(filename=filename).first()

    # Increment the like count for the photo
    photo.like_count += 1

    db.session.commit()

    # Return the updated like count
    return jsonify({"success": True, "likeCount": photo.like_count})




@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    c.execute("SELECT name FROM comments WHERE id = ?", (comment_id,))
    commenter_name = c.fetchone()[0]

    if commenter_name == current_user.username:
        c.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
        conn.commit()

    return redirect(url_for("dashboard"))


@app.route("/delete_photo/<filename>", methods=["POST"])
@login_required
def delete_photo(filename):
    if filename in current_user.profile_photos:
        # Remove the filename from the list
        filenames = current_user.profile_photos.split(",")
        filenames.remove(filename)
        current_user.profile_photos = ",".join(filenames)
        db.session.commit()

        # Delete the file from the filesystem
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(file_path):
            os.remove(file_path)

    return redirect(url_for("dashboard"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    photos = Photo.query.all()
    users = User.query.all()
    c.execute("SELECT * FROM comments ORDER BY id DESC")
    comments = c.fetchall()
    for user in users:
        photo_filenames = user.profile_photos.split(",")
        for filename in photo_filenames:
            photos.append({"filename": filename, "user": user})

    # Sort the photos in reverse order based on the upload timestamp
    photos.sort(
        key=lambda x: os.path.getmtime(
            os.path.join(app.config["UPLOAD_FOLDER"], x["filename"])
        ),
        reverse=True,
    )

    # Retrieve all users who have uploaded photos
    users_with_photos = User.query.filter(User.profile_photo.isnot(None)).all()

    if request.method == "POST":
        if "photo" in request.files:
            photo = request.files["photo"]
            if photo.filename != "":
                filename = secure_filename(photo.filename)
                photo_path = os.path.join("static", "uploads", filename)
                photo.save(photo_path)  # Save the uploaded file

                return render_template(
                    "dashboard.html",
                    username=current_user.username,
                    users_with_photos=users_with_photos,
                    photos=photos,
                    comments=comments,
                )  # Pass the comments to the template

    return render_template(
        "dashboard.html",
        username=current_user.username,
        users_with_photos=users_with_photos,
        photos=photos,
        comments=comments,
    )  # Pass the comments to the template


if __name__ == "__main__":
    app.run(debug=True)
