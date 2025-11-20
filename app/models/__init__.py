"""
Database models for the Hack Club Dashboard application.
All models are imported here for easy access and to ensure proper SQLAlchemy relationships.
"""

# Import all models so SQLAlchemy can track relationships
from app.models.user import User, Role, Permission, RolePermission, UserRole, AuditLog
from app.models.club import Club, ClubMembership, ClubCosmetic, MemberCosmetic
from app.models.club_content import ClubPost, ClubAssignment, ClubMeeting, ClubResource, ClubProject
from app.models.chat import ClubChatMessage
from app.models.attendance import AttendanceSession, AttendanceRecord, AttendanceGuest
from app.models.economy import ClubTransaction, ProjectSubmission, WeeklyQuest, ClubQuestProgress, LeaderboardExclusion
from app.models.gallery import GalleryPost
from app.models.system import SystemSettings, StatusIncident, StatusUpdate
from app.models.shop import ShopItem, Order

from app.models.user import create_audit_log, initialize_rbac_system, migrate_existing_users_to_rbac
from app.models.economy import create_club_transaction, get_current_week_start, update_quest_progress

__all__ = [
    'User', 'Role', 'Permission', 'RolePermission', 'UserRole', 'AuditLog',
    'Club', 'ClubMembership', 'ClubCosmetic', 'MemberCosmetic',
    'ClubPost', 'ClubAssignment', 'ClubMeeting', 'ClubResource', 'ClubProject',
    'ClubChatMessage',
    'AttendanceSession', 'AttendanceRecord', 'AttendanceGuest',
    'ClubTransaction', 'ProjectSubmission', 'WeeklyQuest', 'ClubQuestProgress', 'LeaderboardExclusion',
    'GalleryPost',
    'SystemSettings', 'StatusIncident', 'StatusUpdate',
    'ShopItem', 'Order',
    'create_audit_log', 'initialize_rbac_system', 'migrate_existing_users_to_rbac',
    'create_club_transaction', 'get_current_week_start', 'update_quest_progress',
]
