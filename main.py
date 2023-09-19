import base64
import colorsys
import os
import html
import random
import uuid
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    current_user,
)
from flask_login import logout_user
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash
import secrets
import warnings
import requests
import sqlite3
from datetime import datetime, timedelta, timezone

# Suppressing the warning.
from werkzeug.utils import secure_filename

# Import
from sqlalchemy import UniqueConstraint
from flask_caching import Cache
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message, Mail
import smtplib
import logging



warnings.filterwarnings("ignore", category=DeprecationWarning)

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
UPLOAD_FOLDER_PROFILE = "static/uploads/profile-photo"
SECRET_KEY_VERIFY_CAP = "0xf391442b9432C94165DF28f7B88538b4aC2F983e"
DATABASE = 'reputation.db'

# Sample data for chat messages (you can replace this with a database)
chat_messages = {}

# A dictionary to store user reputations. Replace this with a database.
user_reputations = {}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["UPLOAD_FOLDER_PROFILE"] = UPLOAD_FOLDER_PROFILE
app.secret_key = secrets.token_hex(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"  # SQLite database
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Cache setup
cache = Cache()
app.config['CACHE_TYPE'] = 'redis'  # Use Redis as the caching backend
app.config['CACHE_REDIS_HOST'] = 'localhost'  # Configure the Redis host
app.config['CACHE_REDIS_PORT'] = 6379  # Configure the Redis port
cache.init_app(app)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"


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

# ----------------------

# SQL query to delete duplicate entries in the Friendship table
delete_query = """
    DELETE FROM friendship
    WHERE id NOT IN (
        SELECT MIN(id)
        FROM friendship
        GROUP BY user_id, friend_id
    );
"""

# --- Icons for rank
thresholds_and_icons = [
    (10, '😍'),           # Emoji for 1 photo
    (50, '📸'),          # Emoji for 50 photos
    (100, '🌟'),          # Emoji for 100 photos
    (250, '💎'),         # Emoji for 250 photos
    (500, '👑'),         # Emoji for 500 photos
    (1000, '💯'),        # Emoji for 1000 photos
]

# ---------------------- Reputation
def can_give_reputation(giver_user_id, receiver_user_id):
    # Calculate the datetime 24 hours ago
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)

    # Query the ReputationGiven table to check if the user has given reputation in the last 24 hours
    reputation_given = ReputationGiven.query.filter(
        ReputationGiven.giver_user_id == giver_user_id,
        ReputationGiven.receiver_user_id == receiver_user_id,
        ReputationGiven.timestamp >= twenty_four_hours_ago
    ).first()

    # Return True if they haven't given reputation in the last 24 hours, otherwise False
    return reputation_given is None

# ----------SHOP ITEMS------------

# Function to generate a random hex color code
def generate_random_color():
    # Generate a random color in RGB format
    r, g, b = [int(x * 255) for x in colorsys.hsv_to_rgb(random.random(), 1, 1)]
    return f"#{r:02X}{g:02X}{b:02X}"

# List of available items in the shop
shop_items = [
    {"id": 1, "name": "Photo Border", "price": 100, "border_color": None, "image_url": "/static/images/item1.jpg"},
    {"id": 2, "name": "Color Name", "price": 500, "image_url": "/static/images/item2.jpg"},
    {"id": 3, "name": "Color Comment", "price": 9999, "image_url": "/static/images/item3.jpg"},
]

# ---------------------

# Add this model for tracking likes
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"), nullable=False)

class ReputationGiven(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    giver_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, giver_user_id, receiver_user_id):
        self.giver_user_id = giver_user_id
        self.receiver_user_id = receiver_user_id

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, sender_id, recipient_id, text):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.text = text


# Add a Comment model to your code
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("comments", lazy=True))
    photo = db.relationship("Photo", backref="comments_ref", lazy=True)


class ShopItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)

class PurchasedItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('shop_item.id'), nullable=False)


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("photos", lazy=True))
    likes = db.relationship("Like", backref="photo", lazy=True, cascade="all, delete-orphan")
    comments = db.relationship("Comment", backref="photo_ref", lazy=True, cascade="all, delete-orphan")
    border_color = db.Column(db.String(20))  # Store the border color associated with the photo


class Friendship(db.Model):
    __tablename__ = 'friendship'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __table_args__ = (
        UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)


class Border(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Border name (e.g., "Gold Border")
    color = db.Column(db.String(20), nullable=False)  # Random color for the border
    price = db.Column(db.Integer, nullable=False)      # Price of the border

    def __init__(self, name, color, price):
        self.name = name
        self.color = color
        self.price = price


user_border = db.Table(
    'user_border',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('border_id', db.Integer, db.ForeignKey('border.id'), primary_key=True)
)

followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followee_id', db.Integer, db.ForeignKey('user.id'))
)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, user_id, token):
        self.user_id = user_id
        self.token = token


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_photo = db.Column(db.String(255))  # Add this line
    profile_photos = db.Column(db.String(1000))  # Store a list of filenames
    likes = db.relationship("Like", backref="user", lazy=True)
    reputation = db.Column(db.Integer, default=0)
    last_given_reputation_timestamp = db.Column(db.DateTime, default=None)
    reputation_given_count = db.Column(db.Integer, default=0)
    coins = db.Column(db.Integer, default=10)  # Initialize coins to 10
    selected_border_color = db.Column(db.String(20))  # Store the selected border color
    selected_username_color = db.Column(db.String(7))  # Store color as a hex string (e.g., "#RRGGBB")
    selected_username_comment = db.Column(db.String(7)) # Store color for comment
    uploaded_photo_count = db.Column(db.Integer, default=0)  # Initialize with 0
    trivia_score = db.Column(db.Integer, default=0)  # Add this line to store the trivia score
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(100), nullable=True)
    followers = db.relationship('User', secondary='followers', primaryjoin='User.id==followers.c.followee_id',
                                secondaryjoin='User.id==followers.c.follower_id', backref='following')
    friends = relationship('User', secondary='friendship', primaryjoin=id == Friendship.user_id,
                           secondaryjoin=id == Friendship.friend_id)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email
        self.profile_photo = None  # Set initial value to None
        self.profile_photos = ""  # Initialize the list as an empty string
        self.reputation = 0 # Set the initial reputation count to 0
        self.last_given_reputation_timestamp = None
        self.reputation_given_count = 0
        self.selected_border_color = None  # Initialize selected border color to None
        self.trivia_score = 0  # Initialize the trivia score to 0


    def is_friend_with(self, other_user):
        """
        Check if this user is friends with another user.
        """
        friendship = Friendship.query.filter(
            (Friendship.user_id == self.id) & (Friendship.friend_id == other_user.id)
        ).first()
        return friendship is not None

    def generate_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        self.reset_token = s.dumps({'user_id': self.id}, salt='reset')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def get_reset_token(self):
        return self.reset_token

db.create_all()  # Create database tables if they don't exist

login_manager = LoginManager(app)
login_manager.login_view = "login"

def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            flash('Access denied. You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))  # Redirect unauthorized users
        return func(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()

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

# Reset password -------------- ATTENTION/DANGER CHANGE HERE ----- DANCER
# Decode the pass and mail

email_b = 'aW5zdGFjbG9uZUBhZHJpYW4tYm9nZGFuLmNvbQ=='
pass_b = 'VGVzdDEyM1Rlc3QhQCE='

decoded_bytes = base64.b64decode(email_b)
decoded_bytes_pass = base64.b64decode(pass_b)
decoded_string_mail = decoded_bytes.decode('utf-8')
decoded_string_pass = decoded_bytes_pass.decode('utf-8')

app.config['MAIL_SERVER'] = 'mail.adrian-bogdan.com'
app.config['MAIL_PORT'] = 26
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = decoded_string_mail
app.config['MAIL_PASSWORD'] = decoded_string_pass
app.config['MAIL_DEFAULT_SENDER'] = ('Admin', 'noreply@example.com')

mail = Mail(app)


def send_reset_email(user, reset_link):
    subject = 'Password Reset Request'
    sender_email = app.config['MAIL_USERNAME']
    sender_password = app.config['MAIL_PASSWORD']
    recipient_email = user.email

    message = f"""Subject: {subject}
From: {sender_email}
To: {recipient_email}

To reset your password, visit the following link:
{reset_link}

If you did not make this request, simply ignore this email, and no changes will be made.
"""

    try:
        smtp_server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        smtp_server.starttls()
        smtp_server.login(sender_email, sender_password)
        smtp_server.sendmail(sender_email, recipient_email, message)
        smtp_server.quit()
        flash('An email has been sent to reset your password.', 'success')
    except Exception as e:
        logging.error(f"Email could not be sent: {str(e)}")
        flash('Email could not be sent. Please try again later.', 'danger')



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a unique reset token
            token = secrets.token_urlsafe(32)

            # Create a PasswordReset record
            reset_record = PasswordReset(user_id=user.id, token=token)
            db.session.add(reset_record)
            db.session.commit()

            # Send an email with the reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(user, reset_link)

            flash('An email has been sent to reset your password.', 'success')
            return redirect(url_for('login'))

        flash('Email address not found.', 'danger')

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_record = PasswordReset.query.filter_by(token=token).first()

    if not reset_record:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.get(reset_record.user_id)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            # Update the user's password
            user.password = new_password
            db.session.delete(reset_record)
            db.session.commit()

            flash('Your password has been reset. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))

        flash('Passwords do not match.', 'danger')

    return render_template('reset_password.html', token=token)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    # Check if the user already has a profile photo, and if not, set a default one
    if not current_user.profile_photo:
        current_user.profile_photo = "placeholder.png"  # Set the default profile photo

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        new_password = request.form["password"]
        user_balance = current_user.coins

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
        "profile.html", username=current_user.username, current_user=current_user, user_balance=current_user.coins
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        hcaptcha_response = request.form.get("h-captcha-response")
        secret_key = SECRET_KEY_VERIFY_CAP
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
        new_user.coins = 10  # Initialize coins to 10
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html", error=None)


@app.route("/upload_photo", methods=["POST"])
@login_required
def upload_photo():
    if current_user:
        # Increment the uploaded_photo_count
        current_user.uploaded_photo_count += 1
        db.session.commit()
    else:
        current_user.uploaded_photo_count -= 1
        db.session.commit()


    if "photo" not in request.files:
        flash("No file part")
        return redirect(request.url)

    photo_file = request.files["photo"]

    if photo_file.filename == "":
        flash("No selected file")
        return redirect(request.url)

    if photo_file and allowed_file(photo_file.filename):
        # Generate a unique filename for the photo
        filename = secure_filename(str(uuid.uuid4()) + ".jpg")
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        photo_file.save(file_path)

        # Create a new Photo instance and associate it with the current user
        new_photo = Photo(user_id=current_user.id, filename=filename)

        # Retrieve the user's selected border color from the database
        selected_border_color = current_user.selected_border_color
        new_photo.border_color = selected_border_color

        db.session.add(new_photo)
        db.session.commit()

        flash("Photo uploaded successfully")
        return redirect(url_for("dashboard"))

    flash("Invalid file format. Only JPEG and PNG files are allowed.")
    return redirect(request.url)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/photo/<int:photo_id>')
@login_required
def view_photo(photo_id):
    # Retrieve the photo from the database based on the photo_id
    photo = Photo.query.get(photo_id)
    if photo:
        # You can also fetch comments, likes, or any other relevant data associated with the photo
        comments = Comment.query.filter_by(photo_id=photo_id).all()
        # Render the individual photo page template and pass the photo and comments
        return render_template('photo.html', photo=photo, comments=comments)
    else:
        flash('Photo not found.', 'error')
        return redirect(url_for('dashboard'))


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
        # Increment user's coins by 1
        user.coins -= 1
    else:
        # User hasn't liked the photo, add a like
        new_like = Like(user=user, photo=photo)
        db.session.add(new_like)

        # Increment user's coins by 1
        user.coins += 1

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


@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    # Ensure that the user is authenticated before accessing 'friends'
    if not current_user.is_authenticated:
        return redirect(url_for('login'))  # Redirect to the login page if not logged in

    if request.method == 'POST':
        search_query = request.form.get('search_query')
        # Search for users by username and exclude the current user's username
        search_results = User.query.filter(User.username.ilike(f'%{search_query}%'),
                                           User.username != current_user.username).all()
        return render_template('friends.html', username=current_user.username, search_results=search_results)

    # Display user's friends
    friends = current_user.friends
    return render_template('friends.html', username=current_user.username, friends=friends, chat_messages=chat_messages)


@app.route('/add_friend/<username>', methods=['POST'])
@login_required
def add_friend(username):
    friend = User.query.filter_by(username=username).first()

    if friend:
        # Check if the friendship already exists
        existing_friendship = Friendship.query.filter_by(user_id=current_user.id, friend_id=friend.id).first()

        if existing_friendship:
            return jsonify({'message': f'You are already friends with {friend.username}'})

        # Create a new friendship record
        new_friendship = Friendship(user_id=current_user.id, friend_id=friend.id)
        db.session.add(new_friendship)

        # Automatically add the user to the friend's friend list
        reverse_friendship = Friendship(user_id=friend.id, friend_id=current_user.id)
        db.session.add(reverse_friendship)

        db.session.commit()

        return jsonify({'message': f'You are now friends with {friend.username}'})

    return jsonify({'error': 'User not found'}), 404


@app.route('/remove_friend/<username>', methods=['POST'])
@login_required
def remove_friend(username):
    try:
        friend = User.query.filter_by(username=username).first()
        if friend:
            # Check if the user is already friends with this person
            if current_user.is_friend_with(friend):
                # Remove the friend from the user's list
                current_user.friends.remove(friend)

                # Also, remove the user from the friend's list
                friend.friends.remove(current_user)

                db.session.commit()  # Commit the changes to the database
                cache.clear()  # Clear the cache
                flash(f'{username} has been removed from your friends list.', 'success')
            else:
                flash(f'{username} is not in your friends list.', 'error')
        else:
            flash(f'User {username} not found.', 'error')
    except Exception as e:
        db.session.rollback()  # Rollback the transaction on error
        flash('An error occurred while removing the friend. Please try again.', 'error')
        app.logger.error(f'Error removing friend: {str(e)}')

    return redirect(url_for('friends'))



@app.route('/chat/<username>', methods=['GET', 'POST'])
@login_required
def chat(username):
    friend = User.query.filter_by(username=username).first()
    if friend:
        if request.method == 'POST':
            message = request.form.get('message')
            if message:
                # Create a new message and save it to the database
                new_message = Message(sender_id=current_user.id, recipient_id=friend.id, text=message)
                db.session.add(new_message)
                db.session.commit()

        # Fetch all messages between the current user and the friend
        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == friend.id)) |
            ((Message.sender_id == friend.id) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp).all()

        return render_template('chat.html', friend=friend, messages=messages)
    return 'Friend not found', 404



@app.route('/search_users', methods=['POST'])
@login_required
def search_users():
    search_query = request.form.get('search_query')
    # Perform a search for users by username
    search_results = User.query.filter(User.username.ilike(f'%{search_query}%')).all()
    # Return the search results as JSON
    results = [{'id': user.id, 'username': user.username} for user in search_results]
    return jsonify(results)


@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    data = request.json
    message_text = data.get('message')
    recipient_id = data.get('recipient_id')

    if message_text and recipient_id:
        # Store the message in the database (if used)
        message = Message(sender_id=current_user.id, recipient_id=recipient_id, text=message_text)
        db.session.add(message)
        db.session.commit()

        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Message or recipient missing"}), 400


@app.route('/get_messages/<recipient_id>', methods=['GET'])
@login_required
def get_messages(recipient_id):
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == recipient_id)) |
        ((Message.sender_id == recipient_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp).all()

    messages_data = [{"sender_id": message.sender_id, "text": message.text, "timestamp": message.timestamp}
                     for message in messages]

    return jsonify(messages_data)



@app.route('/user_profile/<username>')
@login_required
def user_profile(username):
    # Check if the user already has a profile photo, and if not, set a default one
    if not current_user.profile_photo:
        current_user.profile_photo = "placeholder.png"  # Set the default profile photo
    # Fetch the user's profile information based on the username
    user = User.query.filter_by(username=username).first()

    if user:
        # Get the user's reputation from the database
        user_reputation = user.reputation  # Replace 'reputation' with the actual field in your User model

        # Retrieve the user's uploaded photos
        user_uploaded_photos = Photo.query.filter_by(user_id=user.id).all()

        # Render the user's profile template and pass the user object, reputation value, and uploaded photos
        return render_template("user_profile.html", user=user, reputation=user_reputation, user_uploaded_photos=user_uploaded_photos)
    else:
        # Handle the case where the user does not exist
        flash("User not found.", "error")
        return redirect(url_for("dashboard"))



@app.route('/give-reputation', methods=['POST'])
@login_required
def give_reputation():
    if request.method == 'POST':
        receiver_user_id = request.json.get('receiver_user_id')

        # Calculate the time left until reputation can be given again
        time_left = calculate_time_left(current_user.last_given_reputation_timestamp)

        # Check if the giver can give reputation to the receiver
        if can_give_reputation(current_user.id, receiver_user_id):
            if time_left.total_seconds() <= 0:
                # Retrieve the receiver user from the database based on receiver_user_id
                receiver_user = User.query.get(receiver_user_id)

                if receiver_user:
                    # Update the reputation count for the receiver
                    receiver_user.reputation += 1  # Increase the reputation count by 1
                    db.session.commit()

                    # Mark that the giver has given reputation to the receiver
                    mark_gave_reputation(current_user.id, receiver_user_id)

                    # Update the last given reputation timestamp for the giver
                    current_user.last_given_reputation_timestamp = datetime.utcnow()
                    db.session.commit()

                    # Return the updated reputation count and next allowed timestamp as JSON response
                    next_allowed_timestamp = datetime.utcnow() + timedelta(seconds=20)
                    return jsonify({
                        'updated_reputation': receiver_user.reputation,
                        'next_allowed_timestamp': next_allowed_timestamp.isoformat(),
                    })
                else:
                    return jsonify({'error': 'Receiver user not found.'})
            else:
                # Return the time left until reputation can be given again as seconds
                return jsonify({'error': 'You can only give reputation once every 24 hours.', 'time_left_seconds': int(time_left.total_seconds())})
        else:
            # If the giver can't give reputation yet, return the error message with time left
            return jsonify({'error': 'You can only give reputation once every 24 hours.', 'time_left_seconds': int(time_left.total_seconds())})

    return jsonify({'error': 'Invalid request'}), 400
# ...

def calculate_time_left(last_given_reputation_timestamp):
    if last_given_reputation_timestamp is None:
        return timedelta(seconds=0)

    # Calculate the datetime 24 hours ago
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)

    # Calculate the time left until reputation can be given again
    time_left = twenty_four_hours_ago - last_given_reputation_timestamp

    return time_left


# ...

def has_given_reputation(giver_user_id, receiver_user_id):
    # Query your database or data structure to check if giver_user_id has given reputation to receiver_user_id
    # Return True if reputation has been given, otherwise return False
    # Example implementation using SQLAlchemy:
    reputation_given = ReputationGiven.query.filter_by(giver_user_id=giver_user_id, receiver_user_id=receiver_user_id).first()
    return reputation_given is not None

def mark_gave_reputation(giver_user_id, receiver_user_id):
    # Create a new record in your database or update your data structure to track this action
    # Example implementation using SQLAlchemy:
    reputation_given = ReputationGiven(giver_user_id=giver_user_id, receiver_user_id=receiver_user_id)
    db.session.add(reputation_given)
    db.session.commit()

@app.route('/update_reputation', methods=['POST'])
def update_reputation():
    if request.method == 'POST':
        # Retrieve the new reputation value from the POST request
        data = request.get_json()
        new_reputation = data.get('reputation')

        if new_reputation is not None:
            # Update the user's reputation in the database (replace 'current_user' with your user object)
            current_user.reputation = new_reputation
            db.session.commit()

            # Return a response indicating success
            return jsonify({'success': True}), 200
        else:
            return jsonify({'error': 'Invalid reputation value'}), 400

    # Handle other HTTP methods or errors
    return jsonify({'error': 'Invalid request'}), 400

# Game Dashboard
# Define the trivia API endpoint
TRIVIA_API_URL = 'https://opentdb.com/api.php?amount=10&type=multiple'


@app.route('/trivia-game', methods=['GET', 'POST'])
@login_required
def trivia_game():
    if request.method == 'GET':
        response = requests.get(TRIVIA_API_URL)
        data = response.json()

        # Decode HTML-encoded entities in questions and answers
        questions = data['results']
        for question in questions:
            question['question'] = html.unescape(question['question'])
            question['correct_answer'] = html.unescape(question['correct_answer'])
            question['incorrect_answers'] = [html.unescape(answer) for answer in question['incorrect_answers']]

        session['questions'] = questions

        return render_template('trivia_game.html', questions=session['questions'], current_question_index=0,
                               feedback=None, completed=False)

    if request.method == 'POST':
        current_question_index = int(request.form['current_question_index'])
        user_answer = request.form['user_answer']
        correct_answer = request.form['correct_answer']

        feedback = "Correct!" if user_answer == correct_answer else "Wrong!"

        # Fetch the next question from the session
        questions = session.get('questions', [])
        next_question = None
        completed = False

        if current_question_index < len(questions) - 1:
            next_question = questions[current_question_index + 1]
        else:
            completed = True

        # Check if the user earned a high score
        if feedback == "Correct!" and current_user.trivia_score < current_question_index + 1:
            current_user.trivia_score = current_question_index + 1

            if feedback == "Correct!":
                current_user.coins += 1
            else:
                current_user.coins -= 1

            db.session.commit()

        return render_template('trivia_game.html', questions=questions,
                               current_question_index=current_question_index + 1, feedback=feedback,
                               next_question=next_question, completed=completed)

@app.route('/update_coins', methods=['POST'])
@login_required
def update_coins():
    try:
        data = request.get_json()
        action = data['action']

        # Ensure the action is 'decrease' before updating coins
        if action == 'decrease':
            # Decrease the user's coins here
            current_user.coins -= 1
            db.session.commit()
            return jsonify({'message': 'User coins decreased successfully'}), 200
        else:
            return jsonify({'error': 'Invalid action'}), 400
    except Exception as e:
        print("Error updating user coins:", str(e))
        db.session.rollback()  # Rollback changes in case of an error
        return jsonify({'error': 'Failed to update user coins'}), 500


# Shop functionality
@app.route('/shop')
@login_required
def shop():
    # Fetch the current user's balance from the database
    user_balance = current_user.coins

    return render_template('shop.html', shop_items=shop_items, user_balance=user_balance)


# Route to handle item purchases
@app.route("/buy_item/<int:item_id>", methods=["POST"])
@login_required
def buy_item(item_id):
    # Get the item from shop_items
    item = next((item for item in shop_items if item["id"] == item_id), None)

    if not item:
        flash("Item not found")
        return redirect(url_for("shop"))

    # Get current user
    user = current_user

    # Validate coins
    if user.coins < item["price"]:
        flash("Insufficient coins")
        return redirect(url_for("shop"))

    # Purchase item
    user.coins -= item["price"]

    if item['name'] == 'Photo Border':
        # Generate a random border color
        random_border_color = generate_random_color()

        # Set the selected border color for the current user
        user.selected_border_color = random_border_color

    elif item['name'] == 'Color Name':
        # Generate a random username color
        random_username_color = generate_random_color()

        # Set the selected username color for the current user
        user.selected_username_color = random_username_color

    elif item['name'] == 'Color Comment':
        # Generate a random comment color
        random_comment_color = generate_random_color()

        # Set the selected username color for the current user
        user.selected_username_comment = random_comment_color

    # Save user
    db.session.commit()

    flash("Item purchased!")

    return redirect(url_for("shop"))


@app.route('/get_balance')
def get_balance():
    return jsonify({'balance': current_user.coins})


@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def modify_user():
    found_user = None

    if request.method == 'POST':
        if 'search_user' in request.form:
            user_id = request.form.get('user_id')
            coins = request.form.get('coins')
            username_to_search = request.form.get('search_username')

            if user_id and coins:
                user_to_modify = User.query.get(int(user_id))
                if user_to_modify:
                    user_to_modify.coins = int(coins)
                    db.session.commit()
                    flash(f'Coins for user {user_to_modify.username} modified to {coins}', 'success')
                else:
                    flash('User not found', 'danger')
            else:
                flash('Please provide both user ID and new coins value', 'danger')

            if username_to_search:
                found_user = User.query.filter_by(username=username_to_search).first()
                if found_user:
                    flash(f'User found: {found_user.username}, ID: {found_user.id}', 'success')
                    session['found_user_id'] = found_user.id
                else:
                    flash('User not found', 'danger')

        elif 'modify_username' in request.form:
            # Modify the username of the found user
            new_username = request.form.get('new_username')
            user_id_modify_username = request.form.get('user_id_modify_username')

            if new_username and user_id_modify_username:
                found_user = User.query.get(int(user_id_modify_username))
                if found_user:
                    found_user.username = new_username
                    db.session.commit()
                    flash('Username modified successfully', 'success')
                else:
                    flash('User not found', 'danger')
            else:
                flash('Please provide both user ID and new username', 'danger')

        elif 'modify_password' in request.form:
            # Modify the password of the found user
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            user_id_modify_password = request.form.get('user_id_modify_password')

            if new_password == confirm_password:
                if new_password and user_id_modify_password:
                    found_user = User.query.get(int(user_id_modify_password))
                    if found_user:
                        # Hash and set the new password (implement your own logic here)
                        found_user.set_password(new_password)
                        db.session.commit()
                        flash('Password modified successfully', 'success')
                    else:
                        flash('User not found', 'danger')
                else:
                    flash('Please provide both user ID and new password', 'danger')
            else:
                flash('Passwords do not match', 'danger')

        elif 'modify_email' in request.form:
            # Modify the email of the found user
            new_email = request.form.get('new_email')
            user_id_modify_email = request.form.get('user_id_modify_email')

            if new_email and user_id_modify_email:
                found_user = User.query.get(int(user_id_modify_email))
                if found_user:
                    found_user.email = new_email
                    db.session.commit()
                    flash('Email modified successfully', 'success')
                else:
                    flash('User not found', 'danger')
            else:
                flash('Please provide both user ID and new email', 'danger')

        elif 'delete_user' in request.form:
            # Delete the found user
            user_id_delete = request.form.get('user_id_delete')

            if user_id_delete:
                found_user = User.query.get(int(user_id_delete))
                if found_user:
                    db.session.delete(found_user)
                    db.session.commit()
                    flash('User deleted successfully', 'success')
                else:
                    flash('User not found', 'danger')
            else:
                flash('Please provide a user ID for deletion', 'danger')

    # Clear the session after processing the request
    session.pop('found_user', None)

    return render_template('admin.html', found_user=found_user, found_user_id=session.get('found_user_id'))

@app.route('/search_user_by_username', methods=['POST'])
def search_user_by_username():
    username = request.json.get('username')

    # Perform the user search by username logic here
    # Replace the following with your actual logic
    found_user = User.query.filter_by(username=username).first()

    if found_user:
        response_data = {'user_id': found_user.id}
    else:
        response_data = {'user_id': None}

    return jsonify(response_data)

@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get(user_id)

    if user_to_follow:
        if user_to_follow not in current_user.following:
            current_user.following.append(user_to_follow)
            db.session.commit()
            print(f"You followed {user_to_follow.username}")
        else:
            print(f"You are already following {user_to_follow.username}")
    else:
        print("User not found")

    return redirect(url_for('user_profile', username=user_to_follow.username))

@app.route('/unfollow/<int:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    user_to_unfollow = User.query.get(user_id)

    if user_to_unfollow is None:
        return jsonify({'error': 'User not found'}), 404

    if user_to_unfollow in current_user.following:
        current_user.following.remove(user_to_unfollow)
        db.session.commit()
        return jsonify({'message': f'Unfollowed {user_to_unfollow.username}'}), 200

    return jsonify({'error': f'You are not following {user_to_unfollow.username}'}), 400



@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    # Retrieve all photos from the database
    photos = Photo.query.all()
    users = User.query.all()
    c.execute("SELECT * FROM comments ORDER BY id DESC")
    comments = c.fetchall()
    user_uploaded_photos = Photo.query.filter_by(user_id=current_user.id).all()

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
                    thresholds_and_icons=thresholds_and_icons,
                    user_uploaded_photos=user_uploaded_photos,
                    user=current_user, # Pass the user's uploaded photos
                )  # Pass the comments to the template

    return render_template(
        "dashboard.html",
        username=current_user.username,
        users_with_photos=users_with_photos,
        photos=photos,
        comments=comments,
        shop_items=shop_items,
        thresholds_and_icons=thresholds_and_icons,
        user_uploaded_photos=user_uploaded_photos,
        user=current_user, # Pass the user's uploaded photos
    )  # Pass the comments to the template

if __name__ == "__main__":
    login_manager.init_app(app)
    # reset_reputation() Reset reputation only once
    # app.run(debug=True)
    app.run(host='192.168.1.135', port=5000, debug=True)