"""
Economy-related decorators for the Hack Club Dashboard.

This module contains decorators for protecting routes that require the economy
system to be enabled. The economy system can be toggled by administrators
through the SystemSettings model.
"""

from functools import wraps
from flask import request, jsonify, flash, redirect, url_for


def economy_required(f):
    """
    Decorator to protect routes that require economy to be enabled.

    Checks if the economy system is enabled in SystemSettings before allowing
    access to the route. Administrators can bypass this check if the admin
    economy override setting is enabled.

    Args:
        f: The function to decorate

    Returns:
        The decorated function

    Usage:
        @app.route('/shop')
        @economy_required
        def shop():
            return render_template('shop.html')

    Notes:
        - Returns JSON error for API requests (request.is_json)
        - Redirects to dashboard with flash message for HTML requests
        - Allows admin access when admin override is enabled
        - Gracefully handles errors by allowing access if settings can't be checked
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        from app.models.system import SystemSettings
        from app.utils.auth_helpers import get_current_user

        try:
            if not SystemSettings.is_economy_enabled():
                current_user = get_current_user()
                if current_user and current_user.is_admin and SystemSettings.is_admin_economy_override_enabled():
                    return f(*args, **kwargs)
                else:
                    if request.is_json:
                        return jsonify({'error': 'This feature is currently disabled.'}), 403
                    flash('This feature is currently disabled.', 'error')
                    return redirect(url_for('dashboard'))
        except Exception as e:
            current_app.logger.error(f"Error checking economy status: {str(e)}")

        return f(*args, **kwargs)
    return decorated_function
