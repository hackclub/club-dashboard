"""
Rate limiting decorators for the Hack Club Dashboard.

This application uses Flask-Limiter for rate limiting, which is configured
in the main application file. Rate limits are applied using the @limiter.limit()
decorator directly on routes.

Example usage in main.py:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    @app.route('/api/endpoint')
    @limiter.limit("10 per minute")
    def rate_limited_endpoint():
        return jsonify({'message': 'Success'})

For more information on Flask-Limiter:
    - Documentation: https://flask-limiter.readthedocs.io/
    - GitHub: https://github.com/alisaifee/flask-limiter

Common rate limiting patterns:
    - Per minute: "10 per minute" or "10/minute"
    - Per hour: "100 per hour" or "100/hour"
    - Per day: "1000 per day" or "1000/day"
    - Multiple limits: ["10 per minute", "100 per hour"]

To import the limiter instance:
    from extensions import limiter

    @limiter.limit("5 per minute")
    def my_route():
        pass

Custom rate limit key functions:
    You can create custom key functions to rate limit by user ID, API key, etc.:

    def get_user_id():
        return str(session.get('user_id', 'anonymous'))

    @limiter.limit("100 per hour", key_func=get_user_id)
    def user_specific_limit():
        pass

Rate limit exemptions:
    To exempt specific routes or conditions:

    @limiter.exempt
    def unlimited_route():
        pass

    Or conditionally:

    @limiter.limit("10 per minute", exempt_when=lambda: current_user.is_admin)
    def conditional_limit():
        pass
"""

