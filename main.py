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
from flask_socketio import emit
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash
import secrets
import warnings
import requests
import sqlite3
from datetime import datetime, timedelta

# Suppressing the warning
from werkzeug.utils import secure_filename

# Import
from sqlalchemy.orm import sessionmaker
from sqlalchemy import UniqueConstraint
from flask_caching import Cache


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

# Assuming you already have SQLAlchemy set up with your app

# Create a session
Session = sessionmaker(bind=db.engine)
session = Session()

# SQL query to delete duplicate entries in the Friendship table
delete_query = """
    DELETE FROM friendship
    WHERE id NOT IN (
        SELECT MIN(id)
        FROM friendship
        GROUP BY user_id, friend_id
    );
"""

try:
    # Execute the query
    session.execute(delete_query)
    session.commit()
    print("Duplicate entries removed successfully.")
except Exception as e:
    session.rollback()
    print(f"Error removing duplicate entries: {str(e)}")
finally:
    session.close()


# ---------------------- Reputation



# ----------------------


# Add this model for tracking likes
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"), nullable=False)

class ReputationGiven(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    giver_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, giver_user_id, receiver_user_id):
        self.giver_user_id = giver_user_id
        self.receiver_user_id = receiver_user_id

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(255), nullable=False)
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


class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("photos", lazy=True))
    likes = db.relationship("Like", backref="photo", lazy=True, cascade="all, delete-orphan")
    comments = db.relationship("Comment", backref="photo_ref", lazy=True, cascade="all, delete-orphan")


class Friendship(db.Model):
    __tablename__ = 'friendship'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __table_args__ = (
        UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),)


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

    def is_friend_with(self, other_user):
        """
        Check if this user is friends with another user.
        """
        friendship = Friendship.query.filter(
            (Friendship.user_id == self.id) & (Friendship.friend_id == other_user.id)
        ).first()
        return friendship is not None


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
def add_friend(username):
    friend = User.query.filter_by(username=username).first()
    if friend:
        # Check if the friendship already exists
        if Friendship.query.filter_by(user_id=current_user.id, friend_id=friend.id).first() is None:
            current_user.friends.append(friend)
            db.session.add(Friendship(user_id=current_user.id, friend_id=friend.id))
            db.session.commit()
            return jsonify({'message': f'You are now friends with {friend.username}'})
        else:
            return jsonify({'message': f'You are already friends with {friend.username}'})
    return jsonify({'error': 'User not found'}), 404


@app.route('/remove_friend/<username>', methods=['POST'])
@login_required
def removeFriend(username):
    try:
        friend = User.query.filter_by(username=username).first()
        if friend:
            # Check if the user is already friends with this person
            if current_user.is_friend_with(friend):
                # Remove the friend from the user's list
                current_user.friends.remove(friend)
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
            # Handle sending the message to the friend and saving it in the database
            # You may need to use Flask-SocketIO or another real-time library for this
            # Emit a real-time message to update the chat interface
            emit('message', {'sender': current_user.username, 'message': message}, room=friend.id)
        # Render the chat interface
        return render_template('chat.html', friend=friend)
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
    message = data.get('message')
    recipient = data.get('recipient')

    if message and recipient:
        # Store the message in the chat_messages dictionary
        if recipient in chat_messages:
            chat_messages[recipient].append(message)
        else:
            chat_messages[recipient] = [message]

        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Message or recipient missing"}), 400


@app.route('/get_messages/<recipient_id>', methods=['GET'])
@login_required
def get_messages(recipient_id):
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id),
        (Message.sender_id == recipient_id) | (Message.recipient_id == recipient_id)
    ).all()
    messages_data = [{"sender_id": message.sender_id, "text": message.text, "timestamp": message.timestamp}
                     for message in messages]
    return jsonify(messages_data)


@app.route('/user_profile/<username>')
@login_required
def user_profile(username):
    # Fetch the user's profile information based on the username
    user = User.query.filter_by(username=username).first()

    if user:
        # Get the user's reputation from the database
        user_reputation = user.reputation  # Replace 'reputation' with the actual field in your User model

        # Render the user's profile template and pass the user object and reputation value
        return render_template("user_profile.html", user=user, reputation=user_reputation)
    else:
        # Handle the case where the user does not exist
        flash("User not found.", "error")
        return redirect(url_for("dashboard"))


@app.route('/give-reputation', methods=['POST'])
@login_required
def give_reputation():
    if request.method == 'POST':
        receiver_user_id = request.form.get('receiver_user_id')

        # Check if the giver has already given reputation to the receiver
        if not has_given_reputation(current_user.id, receiver_user_id):
            # Update the reputation count for the receiver
            receiver_user = User.query.get(receiver_user_id)
            receiver_user.reputation += 1  # Increase the reputation count by 1
            db.session.commit()

            # Mark that the giver has given reputation to the receiver
            mark_gave_reputation(current_user.id, receiver_user_id)

            return jsonify({'success': True, 'message': 'Reputation added successfully.'})
        else:
            return jsonify({'success': False, 'message': 'You can only give reputation once.'})

    return jsonify({'error': 'Invalid request'}), 400

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
    login_manager.init_app(app)
    app.run(debug=True)
