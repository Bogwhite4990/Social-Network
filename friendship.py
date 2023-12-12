from main import db, UniqueConstraint


class Friendship(db.Model):
    __tablename__ = "friendship"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    __table_args__ = (
        UniqueConstraint("user_id", "friend_id", name="unique_friendship"),
    )
