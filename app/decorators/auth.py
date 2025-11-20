"""
Authentication decorators for the Hack Club Dashboard.

This module contains decorators for protecting routes that require authentication,
specific permissions, roles, or API access.
"""

from functools import wraps
from datetime import datetime, timezone
from flask import request, jsonify, flash, redirect, url_for, session
import logging


def login_required(f):
    """
    Decorator to require user authentication.

    Checks if the user is authenticated and not suspended before allowing access to the route.
    For JSON requests, returns 401/403 errors. For HTML requests, redirects to login or suspended page.

    Args:
        f: The function to decorate

    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        from app.utils.auth_helpers import is_authenticated, get_current_user
        from extensions import db
        from app.models.user import User

        authenticated = is_authenticated()
        current_user = get_current_user()

        current_app.logger.debug(f"Auth check for {request.endpoint}: authenticated={authenticated}, user_id={session.get('user_id')}, logged_in={session.get('logged_in')}, current_user={current_user.username if current_user else None}")

        if not authenticated or not current_user:
            current_app.logger.warning(f"Authentication failed for {request.endpoint}: user_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))

        if current_user.is_suspended and request.endpoint not in ['suspended', 'logout']:
            if request.is_json:
                return jsonify({'error': 'Account suspended'}), 403
            return redirect(url_for('suspended'))

        return f(*args, **kwargs)
    return decorated_function


def permission_required(*permissions):
    """
    Decorator to check if user has specific permissions.

    Checks if the authenticated user has at least one of the specified permissions.
    Uses the RBAC (Role-Based Access Control) system.

    Args:
        *permissions: Variable number of permission names to check

    Returns:
        A decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app.utils.auth_helpers import is_authenticated, get_current_user
            from flask import current_app
            from extensions import db
            from app.models.user import User

            authenticated = is_authenticated()
            current_user = get_current_user()

            if not authenticated or not current_user:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('auth.login'))

            has_permission = False
            for perm in permissions:
                if current_user.has_permission(perm):
                    has_permission = True
                    break

            if not has_permission:
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('You do not have permission to access this resource.', 'error')
                return redirect(url_for('main.index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def role_required(*roles):
    """
    Decorator to check if user has specific roles.

    Checks if the authenticated user has at least one of the specified roles.
    Uses the RBAC (Role-Based Access Control) system.

    Args:
        *roles: Variable number of role names to check

    Returns:
        A decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app.utils.auth_helpers import is_authenticated, get_current_user
            from flask import current_app
            from extensions import db
            from app.models.user import User

            authenticated = is_authenticated()
            current_user = get_current_user()

            if not authenticated or not current_user:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('auth.login'))

            has_role = False
            for role in roles:
                if current_user.has_role(role):
                    has_role = True
                    break

            if not has_role:
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('You do not have permission to access this resource.', 'error')
                return redirect(url_for('main.index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """
    Admin access decorator - checks for RBAC admin permissions.

    Checks if the user has admin-level permissions through the RBAC system.
    Accepts users with 'admin.access_dashboard' permission or specific admin roles.

    Args:
        f: The function to decorate

    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.utils.auth_helpers import is_authenticated, get_current_user
        from flask import current_app
        from extensions import db
        from app.models.user import User

        authenticated = is_authenticated()
        current_user = get_current_user()

        if not authenticated or not current_user:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))

        has_admin_access = (
            current_user.has_permission('admin.access_dashboard') or
            current_user.has_role('super-admin') or
            current_user.has_role('admin') or
            current_user.has_role('users-admin')
        )

        if not has_admin_access:
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            flash('Admin access required', 'error')
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)
    return decorated_function


def club_not_suspended(f):
    """
    Decorator to block access to suspended clubs (except for system admins).
    
    This should be used on club-related routes to prevent members/leaders
    from accessing or modifying suspended clubs.
    
    Args:
        f: The function to decorate (must have club_id parameter)
    
    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.utils.auth_helpers import get_current_user
        from app.models.club import Club
        from flask import current_app
        
        club_id = kwargs.get('club_id')
        if not club_id:
            # If no club_id, let the route handle it
            return f(*args, **kwargs)
        
        club = Club.query.get(club_id)
        if not club:
            # If club doesn't exist, let the route handle 404
            return f(*args, **kwargs)
        
        current_user = get_current_user()
        
        # Allow system admins and admin access mode
        is_admin_access = request.args.get('admin') == 'true' and (current_user and current_user.is_admin)
        if current_user and (current_user.is_admin or is_admin_access):
            return f(*args, **kwargs)
        
        # Block access to suspended clubs
        if club.is_suspended:
            current_app.logger.warning(f"Blocked access to suspended club {club_id} by user {current_user.id if current_user else 'anonymous'}")
            if request.is_json:
                return jsonify({'error': 'This club has been suspended and cannot be accessed'}), 403
            flash('This club has been suspended by administrators and cannot be accessed at this time. Please contact clubs@hackclub.com for assistance.', 'error')
            return redirect(url_for('main.dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function


def reviewer_required(f):
    """
    Reviewer access decorator - checks for RBAC reviewer permissions.

    Checks if the user has reviewer-level permissions through the RBAC system.
    Accepts users with 'reviews.submit' permission or specific reviewer/admin roles.

    Args:
        f: The function to decorate

    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.utils.auth_helpers import is_authenticated, get_current_user
        from flask import current_app
        from extensions import db
        from app.models.user import User

        authenticated = is_authenticated()
        current_user = get_current_user()

        if not authenticated or not current_user:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))

        has_reviewer_access = (
            current_user.has_permission('reviews.submit') or
            current_user.has_role('super-admin') or
            current_user.has_role('admin') or
            current_user.has_role('reviewer')
        )

        if not has_reviewer_access:
            if request.is_json:
                return jsonify({'error': 'Reviewer access required'}), 403
            flash('Reviewer access required', 'error')
            return redirect(url_for('main.index'))

        return f(*args, **kwargs)
    return decorated_function


def api_key_required(scopes=None):
    """
    Decorator to require API key authentication.

    Validates API key from Authorization header (Bearer token format).
    Optionally checks if the API key has required scopes.
    Updates the key's last_used_at timestamp on successful authentication.

    Args:
        scopes: Optional list of required scopes

    Returns:
        A decorator function

    Usage:
        @api_key_required(scopes=['read', 'write'])
        def protected_endpoint():
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            from extensions import db
            from app.models.auth import APIKey

            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({
                    'error': 'Missing Authorization header',
                    'error_code': 'MISSING_AUTH_HEADER',
                    'message': 'The Authorization header is required for API access',
                    'how_to_fix': 'Include the Authorization header in your request: "Authorization: Bearer YOUR_API_KEY"'
                }), 401

            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Invalid Authorization header format',
                    'error_code': 'INVALID_AUTH_FORMAT',
                    'message': 'Authorization header must use Bearer token format',
                    'how_to_fix': 'Use the format: "Authorization: Bearer YOUR_API_KEY"',
                    'received': f'Authorization: {auth_header[:50]}...' if len(auth_header) > 50 else f'Authorization: {auth_header}'
                }), 401

            try:
                api_key = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({
                    'error': 'Malformed Authorization header',
                    'error_code': 'MALFORMED_AUTH_HEADER',
                    'message': 'Authorization header is missing the API key',
                    'how_to_fix': 'Ensure your header follows the format: "Authorization: Bearer YOUR_API_KEY"'
                }), 401

            if not api_key or len(api_key) < 10:
                return jsonify({
                    'error': 'Invalid API key format',
                    'error_code': 'INVALID_KEY_FORMAT',
                    'message': 'API key appears to be malformed or too short',
                    'how_to_fix': 'Ensure you are using the complete API key provided by your administrator'
                }), 401

            key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()

            if not key_obj:
                inactive_key = APIKey.query.filter_by(key=api_key, is_active=False).first()
                if inactive_key:
                    return jsonify({
                        'error': 'API key is disabled',
                        'error_code': 'KEY_DISABLED',
                        'message': 'This API key has been disabled by an administrator',
                        'how_to_fix': 'Contact your administrator to reactivate the API key or request a new one'
                    }), 401
                else:
                    return jsonify({
                        'error': 'Invalid API key',
                        'error_code': 'INVALID_API_KEY',
                        'message': 'The provided API key does not exist or has been revoked',
                        'how_to_fix': 'Verify your API key is correct, or contact your administrator for a new one'
                    }), 401

            if scopes:
                key_scopes = key_obj.get_scopes()
                if not any(scope in key_scopes for scope in scopes):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'error_code': 'INSUFFICIENT_SCOPES',
                        'message': f'API key does not have required scopes: {", ".join(scopes)}',
                        'required_scopes': scopes,
                        'available_scopes': key_scopes,
                        'how_to_fix': 'Contact your administrator to add the required scopes to your API key'
                    }), 403

            try:
                key_obj.last_used_at = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as e:
                current_app.logger.error(f"Failed to update API key last_used_at: {e}")

            request.api_key = key_obj
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def oauth_required(scopes=None):
    """
    Decorator to require OAuth token authentication.

    Validates OAuth access token from Authorization header (Bearer token format).
    Checks token expiration and optionally validates required scopes.

    Args:
        scopes: Optional list of required OAuth scopes

    Returns:
        A decorator function

    Usage:
        @oauth_required(scopes=['read:user', 'write:posts'])
        def protected_endpoint():
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            from extensions import db
            from app.models.auth import OAuthToken

            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({
                    'error': 'Missing Authorization header',
                    'error_code': 'MISSING_AUTH_HEADER',
                    'message': 'OAuth access token is required',
                    'how_to_fix': 'Include the Authorization header: "Authorization: Bearer YOUR_ACCESS_TOKEN"'
                }), 401

            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Invalid Authorization header format',
                    'error_code': 'INVALID_AUTH_FORMAT',
                    'message': 'Authorization header must use Bearer token format for OAuth',
                    'how_to_fix': 'Use the format: "Authorization: Bearer YOUR_ACCESS_TOKEN"',
                    'received': f'Authorization: {auth_header[:50]}...' if len(auth_header) > 50 else f'Authorization: {auth_header}'
                }), 401

            try:
                access_token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({
                    'error': 'Malformed Authorization header',
                    'error_code': 'MALFORMED_AUTH_HEADER',
                    'message': 'Authorization header is missing the access token',
                    'how_to_fix': 'Ensure your header follows the format: "Authorization: Bearer YOUR_ACCESS_TOKEN"'
                }), 401

            if not access_token or len(access_token) < 10:
                return jsonify({
                    'error': 'Invalid access token format',
                    'error_code': 'INVALID_TOKEN_FORMAT',
                    'message': 'Access token appears to be malformed or too short',
                    'how_to_fix': 'Ensure you are using the complete access token from the OAuth flow'
                }), 401

            token_obj = OAuthToken.query.filter_by(
                access_token=access_token,
                is_active=True
            ).first()

            if not token_obj:
                inactive_token = OAuthToken.query.filter_by(access_token=access_token, is_active=False).first()
                if inactive_token:
                    return jsonify({
                        'error': 'Access token revoked',
                        'error_code': 'TOKEN_REVOKED',
                        'message': 'This access token has been revoked',
                        'how_to_fix': 'Obtain a new access token by repeating the OAuth authorization flow'
                    }), 401
                else:
                    return jsonify({
                        'error': 'Invalid OAuth token',
                        'error_code': 'INVALID_ACCESS_TOKEN',
                        'message': 'The provided access token does not exist',
                        'how_to_fix': 'Verify your access token is correct, or obtain a new one through the OAuth flow'
                    }), 401

            if token_obj.expires_at < datetime.now(timezone.utc):
                return jsonify({
                    'error': 'OAuth token expired',
                    'error_code': 'TOKEN_EXPIRED',
                    'message': f'Access token expired at {token_obj.expires_at.isoformat()}',
                    'expires_at': token_obj.expires_at.isoformat(),
                    'how_to_fix': 'Use your refresh token to obtain a new access token, or repeat the OAuth authorization flow'
                }), 401

            if scopes:
                token_scopes = token_obj.get_scopes()
                if not any(scope in token_scopes for scope in scopes):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'error_code': 'INSUFFICIENT_SCOPES',
                        'message': f'Access token does not have required scopes: {", ".join(scopes)}',
                        'required_scopes': scopes,
                        'available_scopes': token_scopes,
                        'how_to_fix': 'Request authorization with the required scopes during the OAuth flow'
                    }), 403

            request.oauth_token = token_obj
            request.oauth_user = token_obj.user
            return f(*args, **kwargs)
        return decorated_function
    return decorator
