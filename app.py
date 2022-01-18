import os

from flask import Flask, render_template, request, flash, redirect, session, g, jsonify
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import create_access_token, JWTManager

# from forms import CSRFOnlyForm #FIXME: Add CSRF protection
from models import db, connect_db, User, Question

import dotenv
dotenv.load_dotenv()

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ['JWT_SECRET_KEY']  # Change this!
jwt = JWTManager(app)

# bcrypt= Bcrypt()

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ['DATABASE_URL'].replace("postgres://", "postgresql://"))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
toolbar = DebugToolbarExtension(app)

connect_db(app)

##############################################################################
# User signup/login/logout


@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None

# @app.before_request
# def save_csrf_form_to_g():
#     """Save CSRF form to Flask global."""
#     g.csrf = CSRFOnlyForm()

def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]

@app.post('/signup')
def signup_user():
    """Handles user signup.
    
    Create new user and add to DB. 

    If form not valid, present form.
    """
    # breakpoint()

    # user = User.signup(
    #     username=request.form["username"],
    #     password=request.form["password"],
    #     partner1=request.form["partner1"],
    #     partner2=request.form["partner2"],
    # )

    user = User.signup(
        username=request.json["username"],
        password=request.json["password"],
        partner1=request.json["partner1"],
        partner2=request.json["partner2"],
    )


    serialized = User.serialize(user)
    access_token = create_access_token(identity=serialized)
    return jsonify(token=access_token)

@app.post('/login')
def login_user():
    """Handles user login.

    Logs user in.

    Returns JWT {token:{TOKEN}} on successful login
    else, returns error object.
    """
    # print(request.json)
    print("made it to the backend.")
    #FIXME: Adding backend form validation
    username = request.json["username"]
    password = request.json["password"]

    user = User.authenticate(username, password)
    print("user: ", user)

    if user:
        do_login(user)
        serialized = User.serialize(user)
        token = create_access_token(identity=serialized)
        return jsonify(token=token)
    else:
        return {"errors": "Username/password is incorrect."}
        # refactor: maybe r

