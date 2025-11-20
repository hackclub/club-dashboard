"""
Route blueprints for the Hack Club Dashboard.

This package contains all Flask blueprints organized by functionality:
- main: Home, dashboard, gallery, leaderboard
- auth: Login, signup, OAuth flows
- clubs: Club management, shop, projects
- admin: Admin panel, user/club management, settings
- api: Public API endpoints, admin API
- chat: Club chat messaging
- attendance: Attendance tracking and reporting
- status: Public status page
"""

from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.clubs import clubs_bp
from app.routes.admin import admin_bp
from app.routes.api import api_bp
from app.routes.chat import chat_bp
from app.routes.attendance import attendance_bp
from app.routes.status import status_bp

__all__ = [
    'main_bp',
    'auth_bp',
    'clubs_bp',
    'admin_bp',
    'api_bp',
    'chat_bp',
    'attendance_bp',
    'status_bp',
]
