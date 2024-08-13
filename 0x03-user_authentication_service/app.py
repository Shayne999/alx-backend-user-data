#!/usr/bin/env python3
"""App module"""


from flask import Flask, jsonify, request, abort, redirect, make_response
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound
from auth import _hash_password


app = Flask(__name__)


AUTH = Auth()


@app.route("/", methods=["GET"])
def index():
    """Returns a JSON payload with a message"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """Register a new user"""

    email = request.json.get("email")
    password = request.json.get("password")

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login() -> str:
    """Login a user"""

    email = request.json.get("email")
    password = request.json.get("password")

    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookies("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"])
def delete_session():
    """Delete a user session"""

    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=["GET"])
def profile() -> str:
    """Get a user profile"""

    session_id = request.cookies.get("session_id")
    try:
        user = AUTH.get_user_from_session_id(session_id)
        if user is None:
            abort(403)
        return jsonify({"email": user.email})
    except NoResultFound:
        abort(403)


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token() -> str:
    """Get a reset password token"""

    email = request.form.get("email")
    reset_token = None
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        reset_token = None
    if reset_token is None:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token})


@app.route("/reset_password", methods=["PUT"])
def update_password() -> str:
    """Update a user's password"""

    try:
        email = request.form.get("email")
        reset_token = request.form.get("reset_token")
        new_password = request.form.get("new_password")

        AUTH.update_password(email, reset_token, new_password)

        return jsonify({"email": email, "message": "Password updated"}), 200

    except ValueError:
        return make_response(jsonify({"error": "Invalid token"}), 403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5050")
