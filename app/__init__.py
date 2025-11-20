"""
Hack Club Dashboard Application Factory

This module provides the application factory pattern for creating 
and configuring
the Flask application with all necessary extensions, blueprints, and configurations.
"""

import logging
from flask import Flask, g
from config import Config
from extensions import db, limiter
from better_profanity import profanity
from sqlalchemy.exc import OperationalError, DatabaseError


def create_app(config_class=Config):
    """
    Application factory function.

    Args:
        config_class: Configuration class to use (defaults to Config from config.py)

    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    app.config.from_object(config_class)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    profanity.load_censor_words()

    db.init_app(app)
    limiter.init_app(app)

    with app.app_context():
        from app import models

    register_blueprints(app)

    register_error_handlers(app)

    register_template_helpers(app)

    register_middleware(app)

    initialize_services(app)

    return app


def register_blueprints(app):
    """Register all Flask blueprints for routes"""
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.clubs import clubs_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.chat import chat_bp
    from app.routes.attendance import attendance_bp
    from app.routes.status import status_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(clubs_bp)
    app.register_blueprint(admin_bp)  # Prefix: /admin
    app.register_blueprint(api_bp)  # Prefix: /api
    app.register_blueprint(chat_bp)  # Routes: /api/club/<id>/chat/*
    app.register_blueprint(
        attendance_bp)  # Routes: /api/clubs/<id>/attendance/*
    app.register_blueprint(status_bp)  # Routes: /status, /admin/status/*


def register_error_handlers(app):
    """Register error handlers for common HTTP errors"""
    from flask import render_template, jsonify, request

    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Bad request', 'message': str(e)}), 400
        try:
            return render_template(
                'errors/400.html',
                error_code=400,
                error_title='Bad Request',
                error_message=
                'The request could not be understood by the server.'), 400
        except:
            return '<h1>400 Bad Request</h1>', 400

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith('/api/'):
            return jsonify({
                'error':
                'Forbidden',
                'message':
                'You do not have permission to access this resource'
            }), 403
        try:
            return render_template(
                'errors/403.html',
                error_code=403,
                error_title='Forbidden',
                error_message=
                'You do not have permission to access this resource.'), 403
        except:
            return '<h1>403 Forbidden</h1>', 403

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Not found',
                'message': 'The requested resource was not found'
            }), 404
        try:
            return render_template(
                'errors/404.html',
                error_code=404,
                error_title='Page Not Found',
                error_message='The page you are looking for does not exist.'
            ), 404
        except:
            return '<h1>404 Page Not Found</h1>', 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Too many requests',
                'message': 'Rate limit exceeded'
            }), 429
        try:
            return render_template(
                'errors/429.html',
                error_code=429,
                error_title='Too Many Requests',
                error_message=
                'You have made too many requests. Please try again later.'
            ), 429
        except:
            return '<h1>429 Too Many Requests</h1>', 429

    @app.errorhandler(401)
    def unauthorized(e):
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Authentication is required'
            }), 401
        try:
            return render_template(
                'errors/401.html',
                error_code=401,
                error_title='Unauthorized',
                error_message='You need to be logged in to access this page.'
            ), 401
        except:
            return '<h1>401 Unauthorized</h1>', 401

    @app.errorhandler(405)
    def method_not_allowed(e):
        if request.path.startswith('/api/'):
            return jsonify({
                'error':
                'Method not allowed',
                'message':
                'The request method is not supported for this resource'
            }), 405
        try:
            return render_template(
                'errors/405.html',
                error_code=405,
                error_title='Method Not Allowed',
                error_message=
                'The request method is not supported for this resource.'), 405
        except:
            return '<h1>405 Method Not Allowed</h1>', 405

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.error(f'Internal server error: {str(e)}')
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred'
            }), 500
        try:
            return render_template(
                'errors/500.html',
                error_code=500,
                error_title='Internal Server Error',
                error_message=
                'An unexpected error occurred. We have been notified and are working to fix it.'
            ), 500
        except:
            return '<h1>500 Internal Server Error</h1>', 500

    @app.errorhandler(503)
    def service_unavailable(e):
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Service unavailable',
                'message': 'The service is temporarily unavailable'
            }), 503
        try:
            return render_template(
                'errors/503.html',
                error_code=503,
                error_title='Service Unavailable',
                error_message=
                'The service is temporarily unavailable. Please try again later.'
            ), 503
        except:
            return '<h1>503 Service Unavailable</h1>', 503


def register_template_helpers(app):
    """Register Jinja2 template filters and context processors"""
    from app.utils.sanitization import (markdown_to_html, sanitize_css_color,
                                        sanitize_css_value,
                                        sanitize_html_attribute, sanitize_url)
    from app.utils.auth_helpers import get_current_user
    from app.models.system import SystemSettings

    app.jinja_env.filters['safe_css_color'] = sanitize_css_color
    app.jinja_env.filters['safe_css_value'] = sanitize_css_value
    app.jinja_env.filters['safe_html_attr'] = sanitize_html_attribute
    app.jinja_env.filters['safe_url'] = sanitize_url
    app.jinja_env.filters['markdown'] = markdown_to_html

    @app.context_processor
    def inject_user():
        try:
            return dict(current_user=get_current_user())
        except Exception as e:
            app.logger.error(f"Error injecting user context: {e}")
            return dict(current_user=None)

    @app.context_processor
    def inject_system_settings():
        """Inject system settings helpers into templates"""
        try:
            return dict(
                is_maintenance_mode=SystemSettings.is_maintenance_mode(),
                is_economy_enabled=SystemSettings.is_economy_enabled(),
                is_mobile_enabled=SystemSettings.is_mobile_enabled(),
                economy_enabled=SystemSettings.is_economy_enabled()  # Legacy compatibility
            )
        except Exception as e:
            app.logger.error(f"Error injecting system settings: {e}")
            # Return safe defaults if database is unavailable
            return dict(
                is_maintenance_mode=False,
                is_economy_enabled=False,
                is_mobile_enabled=False,
                economy_enabled=False
            )

    @app.context_processor
    def inject_cosmetics_functions():
        """Inject cosmetics helper functions for templates"""
        import html
        from app.utils.sanitization import sanitize_html_attribute
        from app.models.club import MemberCosmetic
        from app.models.user import User

        def get_member_cosmetics(club_id, user_id):
            """Get cosmetic effects for a club member"""
            cosmetic = MemberCosmetic.query.filter_by(club_id=club_id,
                                                      user_id=user_id).first()
            return cosmetic.cosmetic_type if cosmetic else None

        def get_cosmetic_css_class(effects):
            """Convert cosmetic effects to CSS class"""
            if not effects:
                return ''
            effect_classes = {
                'rainbow': 'rainbow-text',
                'glow': 'glow-text',
                'sparkle': 'sparkle-text',
                'fire': 'fire-text'
            }
            return effect_classes.get(effects, '')

        def apply_member_cosmetics(club_id, user_id, username):
            """Apply cosmetic effects to a member's username"""
            user = User.query.get(user_id)
            escaped_username = html.escape(username) if username else ''
            result = escaped_username

            if user and user.is_admin:
                result = f'{escaped_username} <i class="fas fa-bolt" style="color: #fbbf24; margin-left: 4px;" title="Admin"></i>'

            effects = get_member_cosmetics(club_id, user_id)
            if effects:
                css_class = get_cosmetic_css_class(effects)
                if css_class:
                    safe_css_class = sanitize_html_attribute(css_class)
                    result = f'<span class="{safe_css_class}">{result}</span>'

            return result

        return dict(get_member_cosmetics=get_member_cosmetics,
                    get_cosmetic_css_class=get_cosmetic_css_class,
                    apply_member_cosmetics=apply_member_cosmetics)

    from flask import url_for as flask_url_for

    @app.context_processor
    def override_url_for():
        """Provide backward compatibility for old endpoint names"""

        def url_for_compat(endpoint, **values):
            endpoint_map = {
                'static': 'static',
                'index': 'main.index',
                'dashboard': 'main.dashboard',
                'gallery': 'main.gallery',
                'leaderboard': 'main.leaderboard',
                'maintenance': 'main.maintenance',
                'account': 'main.account',
                'contact': 'main.contact',
                'login': 'auth.login',
                'logout': 'auth.logout',
                'signup': 'auth.signup',
                'forgot_password': 'auth.forgot_password',
                'reset_password': 'auth.reset_password',
                'verify_email': 'auth.verify_email',
                'verify_reset_code': 'auth.verify_reset_code',
                'verify_leader': 'auth.verify_leader',
                'setup_hackatime': 'auth.setup_hackatime',
                'club_dashboard': 'main.club_dashboard',
                'club_shop': 'clubs.club_shop',
                'club_orders': 'clubs.club_orders',
                'poster_editor': 'clubs.poster_editor',
                'project_submission': 'clubs.project_submission',
                'blog': 'blog.blog_index',
                'blog_list': 'blog.blog_index',
                'blog_post': 'blog.blog_post',
                'blog_detail': 'blog.blog_post',
                'blog_create': 'blog.blog_create',
                'blog_edit': 'blog.blog_edit',
                'blog_delete': 'blog.blog_delete',
                'admin': 'admin.dashboard',
                'admin_dashboard': 'admin.dashboard',
                'admin_users': 'admin.admin_users',
                'admin_clubs': 'admin.admin_clubs',
                'admin_settings': 'admin.admin_settings',
            }

            endpoint = endpoint_map.get(endpoint, endpoint)

            return flask_url_for(endpoint, **values)

        return dict(url_for=url_for_compat)


def register_middleware(app):
    """Register middleware and before/after request handlers"""
    from flask import request, session, redirect, url_for, render_template, make_response
    from app.models.system import SystemSettings
    from app.utils.security import add_security_headers, get_real_ip

    def check_database_health():
        """Check if database is accessible"""
        if hasattr(g, 'database_healthy'):
            return g.database_healthy
        
        try:
            # Simple query to check database connectivity
            db.session.execute(db.text('SELECT 1'))
            g.database_healthy = True
            return True
        except (OperationalError, DatabaseError) as e:
            app.logger.error(f"Database health check failed: {e}")
            g.database_healthy = False
            return False
        except Exception as e:
            app.logger.error(f"Unexpected error in database health check: {e}")
            g.database_healthy = False
            return False

    @app.before_request
    def check_database_before_request():
        """Check database health before each request"""
        # Skip database check for static files
        if request.endpoint == 'static':
            return None
        
        # Check if database is healthy
        if not check_database_health():
            try:
                return make_response(render_template('errors/database_error.html'), 503)
            except Exception:
                # If template rendering fails, return a simple HTML response
                return '''
                <!DOCTYPE html>
                <html>
                <head><title>Database Error</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1>503 - Service Unavailable</h1>
                    <p>Our servers are experiencing technical difficulties.</p>
                    <p>Please try again in a few minutes.</p>
                    <button onclick="location.reload()">Retry</button>
                </body>
                </html>
                ''', 503

    @app.before_request
    def check_maintenance_mode():
        """Check if maintenance mode is enabled and redirect if necessary"""
        # Allow access to maintenance page, static files, and auth endpoints
        if request.endpoint in ['main.maintenance', 'static', 'auth.login', 'auth.logout', 'auth.verify_2fa']:
            return None

        try:
            if SystemSettings.is_maintenance_mode():
                from app.utils.auth_helpers import get_current_user
                user = get_current_user()
                if not user or not user.is_admin:
                    from flask import render_template
                    try:
                        return render_template('maintenance.html'), 503
                    except:
                        return '<h1>System Maintenance</h1><p>We are currently performing maintenance. Please check back soon.</p>', 503
        except Exception as e:
            app.logger.error(f"Error checking maintenance mode: {e}")
            db.session.rollback()

        return None

    @app.before_request
    def check_2fa_requirement():
        """Check if user needs 2FA enabled for their roles"""
        # Skip check for certain endpoints
        excluded_endpoints = [
            'auth.require_2fa', 'auth.setup_2fa', 'auth.disable_2fa',
            'auth.logout', 'static', 'auth.verify_2fa',
            'auth.regenerate_backup_codes'
        ]
        
        if request.endpoint in excluded_endpoints:
            return None
        
        # Skip check for API endpoints (they handle auth differently)
        if request.endpoint and request.endpoint.startswith('api.'):
            return None
        
        from app.utils.auth_helpers import get_current_user, is_authenticated
        
        if not is_authenticated():
            return None
        
        user = get_current_user()
        if not user:
            return None
        
        # If user has roles requiring 2FA but hasn't enabled it, redirect
        if user.requires_2fa() and not user.totp_enabled:
            return redirect(url_for('auth.require_2fa'))
        
        return None

    @app.after_request
    def after_request(response):
        """Add security headers to all responses"""
        return add_security_headers(response)

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        """Remove database session after each request"""
        try:
            db.session.remove()
        except Exception as e:
            app.logger.error(f"Error removing session: {e}")


def initialize_services(app):
    """Initialize external service integrations"""
    from app.services.airtable import AirtableService
    from app.services.hackatime import HackatimeService
    from app.services.identity import HackClubIdentityService
    with app.app_context():
        pass
