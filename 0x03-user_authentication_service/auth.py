#!/usr/bin/env python3
""""Auth module"""


from user import User
from db import DB
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
from uuid import uuid4
from typing import Union


def _hash_password(password: str) -> str:
    """Hashes a password"""
    from bcrypt import hashpw, gensalt
    return hashpw(password.encode(), gensalt()).decode()


def _generate_uuid() -> str:
    """Generates a UUID"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Validates login credentials"""
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                hashed_password_bytes = user.hashed_password.encode(
                    "utf-8") if isinstance(
                        user.hashed_password, str) else user.hashed_password

                return bcrypt.checkpw(
                    password.encode("utf-8"), hashed_password_bytes)

        except NoResultFound:
            pass
        return False

    def create_session(self, email: str) -> str:
        """Creates a session for a user"""
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                session_id = _generate_uuid()
                self._db.update_user(user.id, session_id=session_id)
                return session_id
        except NoResultFound:
            pass
        return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Get a user from a session ID"""

        user = None

        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session"""
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Get a reset password token"""
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Update a user's password"""
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        new_password_hash = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_password_hash,
            reset_token=None,
        )
