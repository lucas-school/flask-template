import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import logging

from helpers import broadcast, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    # render index.html
    return render_template("index.html")



@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():

    # if user reached route via POST
    if request.method == "POST":

        # initialize variables for the username, password and password confirmation from the registration form

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # if no username is submitted, apologize
        if not username:
            broadcast("Please provide a username.")
            return render_template("register.html")

        # if no password is submitted, apologize
        elif not password:
            broadcast("Please provide a password.")
            return render_template("register.html")

        # if no password confirmation is submitted, apologize
        elif not confirmation:
            broadcast("Please confirm your password.")
            return render_template("register.html")

        # check the username against the database to make sure it hasn't already been inputted
        elif len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0:
            broadcast("Username is already in use.")
            return render_template("register.html")

        # check confirmation password and inputted passwords match
        elif not confirmation == password:
            broadcast("Passwords need to match.")
            return render_template("register.html")

        else:

            # generate password hash and input the new username and password into the database
            password_hash = generate_password_hash(password, "sha256")
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", username, password_hash)

            # redirect user back to their home page
            return redirect("/")

    # if user reached route via GET
    else:
        return render_template("register.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():

    # if user reached route via POST
    if request.method == "POST":

        # initialize variables for the new + old password and password confirmation from the form
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # query database for current user's current password
        rows = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])

        # if no old password is submitted, apologize
        if not old_password:
            broadcast("Please provide your old password.")
            return render_template("change_password.html")

        # if no new password is submitted, apologize
        if not new_password:
            broadcast("Please provide a new password.")
            return render_template("change_password.html")

        # if no password confirmation is submitted, apologize
        elif not confirmation:
            broadcast("Please confirm your new password.")
            return render_template("change_password.html")

        # check confirmation password and inputted passwords match
        elif not confirmation == new_password:
            broadcast("Passwords need to match.")
            return render_template("change_password.html")

        # check the old password matches what's in the database
        elif not check_password_hash(rows[0]["hash"], old_password):
            broadcast("Incorrect old password.")
            return render_template("change_password.html")

        else:

            # generate password hash and input the new username and password into the database
            password_hash = generate_password_hash(new_password, "sha256")
            db.execute("UPDATE users SET hash = :newpass WHERE id = :id",  newpass=password_hash, id=session["user_id"])

            # redirect user back to their home page
            return redirect("/")

    # if user reached route via GET
    else:
        return render_template("change_password.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            broadcast("Please provide a username.")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            broadcast("Please provide a password.")
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            broadcast("Invalid username and/or password.")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return broadcast(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)