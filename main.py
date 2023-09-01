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
    """CREATE TABLE IF NOT EXISTS photos
             (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, user_id INTEGER)"""
)
c.execute(
    """CREATE TABLE IF NOT EXISTS comments
             (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, comment TEXT)"""
)
conn.commit()
db = SQLAlchemy(app)


# Add this model for tracking likes
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"), nullable=False)


# Add a Comment model to your code
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("comments", lazy=True))
    photo = db.relationship("Photo", backref="comments_ref", lazy=True)


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("photos", lazy=True))
    likes = db.relationship("Like", backref="photo", lazy=True)
    comments = db.relationship("Comment", backref="photo_ref", lazy=True, cascade="all, delete-orphan")


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_photo = db.Column(db.String(255))  # Add this line
    profile_photos = db.Column(db.String(1000))  # Store a list of filenames
    likes = db.relationship("Like", backref="user", lazy=True)

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

            # Save the photo to the database
            new_photo = Photo(filename=filename, user_id=current_user.id)
            db.session.add(new_photo)
            db.session.commit()

            # Print the ID of the newly uploaded photo
            # print(f"Uploaded photo with ID: {new_photo.id}")

            # Save the file to the 'uploads' folder (if needed)
            photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            photo.save(photo_path)

    return redirect(url_for("dashboard"))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/like_photo/<int:photo_id>", methods=["POST"])
@login_required
def like_photo(photo_id):
    photo = Photo.query.get(photo_id)

    if not photo:
        return jsonify({"error": "Photo not found"})

    user = current_user
    like = Like.query.filter_by(user_id=user.id, photo_id=photo.id).first()

    if like:
        # User has already liked the photo, remove the like
        db.session.delete(like)
    else:
        # User hasn't liked the photo, add a like
        new_like = Like(user=user, photo=photo)
        db.session.add(new_like)

    db.session.commit()

    # Return the updated like count
    like_count = len(photo.likes)
    return jsonify({"like_count": like_count})


# Create a new route to add comments
@app.route("/add_comment", methods=["POST"])
@login_required
def add_comment():
    photo_id = request.form.get("photo_id")
    comment_text = request.form.get("comment")

    if photo_id and comment_text:
        # Create a new comment and save it in the database
        new_comment = Comment(text=comment_text, user=current_user, photo_id=photo_id)
        db.session.add(new_comment)
        db.session.commit()

    return redirect(url_for("dashboard"))


# Create a route to delete comments
@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)

    if comment and comment.user == current_user:
        db.session.delete(comment)
        db.session.commit()

    return redirect(url_for("dashboard"))


@app.route("/delete_photo/<int:photo_id>", methods=["POST"])
@login_required
def delete_photo(photo_id):
    photo = Photo.query.get(photo_id)

    if photo:
        if photo.user_id == current_user.id:
            # Manually delete associated comments
            comments_to_delete = Comment.query.filter_by(photo_id=photo.id).all()
            for comment in comments_to_delete:
                db.session.delete(comment)

            # Delete the photo
            db.session.delete(photo)
            db.session.commit()

            # Delete the file from the filesystem (if needed)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], photo.filename)
            if os.path.exists(file_path):
                os.remove(file_path)

            flash("Photo deleted successfully.", "success")
        else:
            flash("You do not have permission to delete this photo.", "error")
    else:
        flash("Photo not found.", "error")

    return redirect(url_for("dashboard"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    # Retrieve all photos from the database
    photos = Photo.query.all()
    users = User.query.all()
    c.execute("SELECT * FROM comments ORDER BY id DESC")
    comments = c.fetchall()
    for user in users:
        photo_filenames = user.profile_photos.split(",")
        for filename in photo_filenames:
            photos.append(Photo(filename=filename, user=user))  # Append Photo objects

    # Sort the photos in reverse order based on the upload timestamp
    photos.sort(
        key=lambda x: os.path.getmtime(
            os.path.join(app.config["UPLOAD_FOLDER"], x.filename)
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
