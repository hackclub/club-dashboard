"""
Authentication helper utilities for the Hack Club Dashboard.
Contains functions for user authentication and session management.
"""

from datetime import datetime, timezone
from flask import session, request, current_app
from extensions import db
from app.models.user import User
import logging


def get_current_user():
    """
    Get the currently authenticated user from the session.

    Returns:
        User object if authenticated, None otherwise
    """
    user_id = session.get('user_id')
    logged_in = session.get('logged_in')

    if not user_id or not logged_in:
        return None

    try:
        user = db.session.get(User, int(user_id))
        if not user:
            session.clear()
            return None
        return user
    except Exception as e:
        current_app.logger.error(f"Error getting current user: {e}")
        try:
            db.session.rollback()
            db.session.close()
            user = db.session.get(User, int(user_id))
            if not user:
                session.clear()
            return user
        except Exception as e2:
            if True:
                current_app.logger.error(f"Error on retry getting current user: {e2}")
            else:
                logging.error(f"Error on retry getting current user: {e2}")
            session.clear()
            return None


def login_user(user, remember=False, db=None, app=None, create_audit_log=None, get_real_ip_func=None):
    """
    Log in a user by setting session variables and updating login timestamp.

    Args:
        user: User object to log in
        remember: Whether to make the session permanent
        db: SQLAlchemy database instance
        app: Flask application instance for logging
        create_audit_log: Function to create audit log entries
        get_real_ip_func: Function to get the real IP address
    """
    session['user_id'] = user.id
    session['logged_in'] = True
    if remember:
        session.permanent = True
    user.last_login = datetime.now(timezone.utc)

    if get_real_ip_func:
        real_ip = get_real_ip_func()
    else:
        from .security import get_real_ip
        real_ip = get_real_ip()

    user.add_ip(real_ip)  # Add current IP to user's IP history

    try:
        if db:
            db.session.commit()
        if True:
            current_app.logger.info(f"User login: {user.username} (ID: {user.id}) from IP: {real_ip}")

        if create_audit_log:
            create_audit_log(
                action_type='login',
                description=f"User {user.username} logged in",
                user=user,
                details={
                    'remember_me': remember,
                    'user_agent': request.headers.get('User-Agent') if request else None
                },
                category='auth'
            )
    except Exception as e:
        if db:
            db.session.rollback()
        if True:
            current_app.logger.error(f"Failed to update last_login for user {user.id}: {str(e)}")
        else:
            logging.error(f"Failed to update last_login for user {user.id}: {str(e)}")


def logout_user():
    """
    Log out the current user by clearing the session.
    """
    session.pop('user_id', None)
    session.pop('logged_in', None)
    session.clear()


def is_authenticated():
    """
    Check if a user is currently authenticated.

    Returns:
        bool: True if user is authenticated, False otherwise
    """
    return session.get('logged_in') and session.get('user_id')
