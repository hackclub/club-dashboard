"""
Club models for managing clubs, memberships, and cosmetics.
"""
import json
import secrets
import string
from datetime import datetime, timezone
from extensions import db


class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(255))
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    co_leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    join_code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    balance = db.Column(db.Numeric(10, 2), default=0.00)
    tokens = db.Column(db.Integer, default=0, nullable=False)
    piggy_bank_tokens = db.Column(db.Integer, default=0, nullable=False)
    __table_args__ = (
        db.CheckConstraint('tokens >= 0', name='check_tokens_non_negative'),
        db.CheckConstraint('piggy_bank_tokens >= 0', name='check_piggy_bank_tokens_non_negative'),
    )
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    sync_immune = db.Column(db.Boolean, default=False, nullable=False)  # If True, bypasses intrusive connection popup
    background_image_url = db.Column(db.String(500), nullable=True)  # Custom background image URL
    background_blur = db.Column(db.Integer, default=0)  # Blur intensity (0-100)
    airtable_data = db.Column(db.Text)  # JSON field for additional Airtable metadata
    team_notes = db.Column(db.Text, nullable=True)  # Internal team notes for club leaders

    leader = db.relationship('User', foreign_keys=[leader_id], backref='led_clubs')
    co_leader = db.relationship('User', foreign_keys=[co_leader_id], backref='co_led_clubs')
    members = db.relationship('ClubMembership', back_populates='club', cascade='all, delete-orphan')

    def generate_join_code(self):
        self.join_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def get_airtable_data(self):
        """Get parsed Airtable data"""
        try:
            return json.loads(self.airtable_data) if self.airtable_data else {}
        except:
            return {}

    def set_airtable_data(self, data):
        """Set Airtable data as JSON"""
        self.airtable_data = json.dumps(data)

    @property
    def total_tokens(self):
        """Alias for tokens field for template compatibility"""
        return self.tokens


class ClubMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='club_memberships')
    club = db.relationship('Club', back_populates='members')


class ClubCosmetic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    cosmetic_id = db.Column(db.String(100), nullable=False)  # e.g., 'rainbow_name', 'vip_role'
    cosmetic_type = db.Column(db.String(50), nullable=False)  # 'name_effect', 'role', 'badge', 'effect'
    cosmetic_name = db.Column(db.String(200), nullable=False)
    price_paid = db.Column(db.Float, nullable=False)  # USD amount paid
    purchased_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)  # For time-limited cosmetics
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    club = db.relationship('Club', backref=db.backref('cosmetics', lazy=True, cascade='all, delete-orphan'))


class MemberCosmetic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    club_cosmetic_id = db.Column(db.Integer, db.ForeignKey('club_cosmetic.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Leader who assigned it
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('member_cosmetics', lazy=True))
    club = db.relationship('Club', backref=db.backref('member_cosmetics_list', lazy=True, cascade='all, delete-orphan'))
    club_cosmetic = db.relationship('ClubCosmetic', backref=db.backref('member_assignments', lazy=True, cascade='all, delete-orphan'))
    assigned_by_user = db.relationship('User', foreign_keys=[assigned_by])
