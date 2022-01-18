"""SQLAlchemy models for Therapy Game."""

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

bcrypt = Bcrypt()
db = SQLAlchemy()

class User(db.Model):
    """Users/Couples in system."""

    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    username = db.Column(
        db.Text,
        nullable=False,
        unique=True,
    )

    password = db.Column(
        db.Text,
        nullable=False,
    )

    partner1 = db.Column(
        db.Text,
        nullable=False,
    )

    partner2 = db.Column(
        db.Text,
        nullable=False,
    )

    def __repr__(self):
        return f"<User #{self.id}: Partner1-{self.partner1}, Partner2-{self.partner2}>"

    @classmethod
    def serialize(cls, self):
        """Serialize to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "partner1": self.partner1,
            "partner2": self.partner2,
        }

    @classmethod
    def signup(cls, username, password, partner1, partner2):
        """Sign up user.

        Hashes password and adds user to system.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            username=username,
            password=hashed_pwd,
            partner1=partner1,
            partner2=partner2,
        )

        db.session.add(user)
        db.session.commit()
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Find user with `username` and `password`.

        This is a class method (call it on the class, not an individual user.)
        It searches for a user whose password hash matches this password
        and, if it finds such a user, returns that user object.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username).first()

        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False

class Question(db.Model):
    """Questions in system."""

    __tablename__ = 'questions'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    question = db.Column(
        db.Text,
        nullable=False,
    )

    dificulty = db.Column(
        db.Integer,
        nullable=False,
    )

def connect_db(app):
    """Connect this database to provided Flask app.

    You should call this in your Flask app.
    """

    db.app = app
    db.init_app(app)