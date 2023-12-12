from main import app, login_required, Photo

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    # Retrieve all photos from the database
    photos = Photo.query.all()
    users = User.query.all()
    c.execute("SELECT * FROM comments ORDER BY id DESC")
    comments = c.fetchall()
    user_uploaded_photos = Photo.query.filter_by(user_id=current_user.id).all()
    # Get the current user's ID
    user_id = current_user.id if current_user else None
    is_admin = current_user.id == 1

    for user in users:
        photo_filenames = user.profile_photos.split(",")
        for filename in photo_filenames:
            photos.append(Photo(filename=filename, user=user))  # Append Photo objects.

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
                    user=current_user,  # Pass the user's uploaded photos
                    user_id=user_id,  # Pass the user's ID
                    is_admin=is_admin,  # Pass the admin status
                )

    return render_template(
        "dashboard.html",
        username=current_user.username,
        users_with_photos=users_with_photos,
        photos=photos,
        comments=comments,
        shop_items=shop_items,
        thresholds_and_icons=thresholds_and_icons,
        user_uploaded_photos=user_uploaded_photos,
        user=current_user,  # Pass the user's uploaded photos
        user_id=user_id,  # Pass the user's ID
        is_admin=is_admin,  # Pass the admin status
    )
