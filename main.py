"""
Hack Club Dashboard - Application Entry Point
Main entry point for the Flask application using the modularized structure.
"""
import os
from app import create_app

# Create the Flask application instance
app = create_app()

if __name__ == '__main__':
    from extensions import db

    try:
        with app.app_context():
            db.create_all()
            app.logger.info("Database tables created successfully")
    except Exception as e:
        app.logger.error(f"Database setup error: {e}")

    port = int(os.getenv('PORT', 5000))
    app.logger.info(f"Starting Hack Club Dashboard on port {port}")

    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')
