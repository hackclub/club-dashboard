"""
System settings and status management models.
"""
import json
from datetime import datetime, timezone
from flask import current_app
from extensions import db


class SystemSettings(db.Model):
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    updated_by_user = db.relationship('User', backref=db.backref('system_settings_updates', lazy=True))

    @staticmethod
    def get_setting(key, default=None):
        """Get a system setting value"""
        try:
            setting = SystemSettings.query.filter_by(key=key).first()
            return setting.value if setting else default
        except Exception as e:
            current_app.logger.error(f"Error getting setting '{key}': {str(e)}")
            db.session.rollback()
            return default

    @staticmethod
    def set_setting(key, value, user_id=None):
        """Set a system setting value"""
        try:
            from app.models.user import User

            setting = SystemSettings.query.filter_by(key=key).first()
            if setting:
                setting.value = str(value)
                if user_id:
                    user_exists = db.session.query(User.query.filter(User.id == user_id).exists()).scalar()
                    if user_exists:
                        setting.updated_by = user_id
            else:
                valid_user_id = None
                if user_id:
                    user_exists = db.session.query(User.query.filter(User.id == user_id).exists()).scalar()
                    if user_exists:
                        valid_user_id = user_id
                setting = SystemSettings(key=key, value=str(value), updated_by=valid_user_id)
                db.session.add(setting)

            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error setting '{key}': {str(e)}")
            return False

    @staticmethod
    def get_bool_setting(key, default=False):
        """Get a boolean system setting"""
        value = SystemSettings.get_setting(key, str(default))
        return value.lower() in ('true', '1', 'yes', 'on')

    @staticmethod
    def is_maintenance_mode():
        """Check if maintenance mode is enabled"""
        return SystemSettings.get_bool_setting('maintenance_mode', False)

    @staticmethod
    def is_economy_enabled():
        """Check if economy is enabled"""
        return SystemSettings.get_bool_setting('economy_enabled', True)

    @staticmethod
    def is_admin_economy_override_enabled():
        """Check if admin economy override is enabled"""
        return SystemSettings.get_bool_setting('admin_economy_override', False)

    @staticmethod
    def is_club_creation_enabled():
        """Check if club creation is enabled"""
        return SystemSettings.get_bool_setting('club_creation_enabled', True)

    @staticmethod
    def is_user_registration_enabled():
        """Check if user registration is enabled"""
        return SystemSettings.get_bool_setting('user_registration_enabled', True)

    @staticmethod
    def is_mobile_enabled():
        """Check if mobile dashboard is enabled"""
        return SystemSettings.get_bool_setting('mobile_enabled', True)


class StatusIncident(db.Model):
    __tablename__ = 'status_incident'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='investigating')  # investigating, identified, monitoring, resolved
    impact = db.Column(db.String(50), nullable=False, default='minor')  # minor, major, critical
    affected_services = db.Column(db.Text)  # JSON array of affected services
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('created_incidents', lazy=True))

    def get_affected_services(self):
        """Get affected services as a list"""
        if self.affected_services:
            try:
                return json.loads(self.affected_services)
            except:
                return []
        return []

    def set_affected_services(self, services_list):
        """Set affected services from a list"""
        self.affected_services = json.dumps(services_list)

    def get_duration(self):
        """Get incident duration in human readable format"""
        if self.resolved_at:
            resolved_at = self.resolved_at
            if resolved_at.tzinfo is None:
                resolved_at = resolved_at.replace(tzinfo=timezone.utc)
            created_at = self.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            delta = resolved_at - created_at
        else:
            created_at = self.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - created_at

        total_seconds = int(delta.total_seconds())
        if total_seconds < 0:
            return "0s"  # Handle negative durations
        elif total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            return f"{total_seconds // 60}m"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days}d {hours}h"

    def to_dict(self):
        def format_timestamp(dt):
            """Format timestamp ensuring timezone info"""
            if not dt:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()

        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'impact': self.impact,
            'affected_services': self.get_affected_services(),
            'created_at': format_timestamp(self.created_at),
            'updated_at': format_timestamp(self.updated_at),
            'resolved_at': format_timestamp(self.resolved_at),
            'duration': self.get_duration(),
            'creator': {
                'id': self.creator.id,
                'username': self.creator.username
            } if self.creator else None
        }


class StatusUpdate(db.Model):
    __tablename__ = 'status_update'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('status_incident.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False)  # investigating, identified, monitoring, resolved
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    incident = db.relationship('StatusIncident', backref=db.backref('updates', lazy=True, order_by='StatusUpdate.created_at'))
    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('status_updates', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'creator': {
                'id': self.creator.id,
                'username': self.creator.username
            } if self.creator else None
        }
