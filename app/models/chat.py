"""
Chat models for club messaging.
"""
from datetime import datetime, timezone
from extensions import db


class ClubChatMessage(db.Model):
    __tablename__ = 'club_chat_messages'

    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(1000), nullable=True)  # 1000 char limit, nullable for image-only messages
    image_url = db.Column(db.String(500), nullable=True)  # URL to image on CDN
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref=db.backref('chat_messages', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('club_chat_messages', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'club_id': self.club_id,
            'user_id': self.user_id,
            'username': self.user.username,
            'message': self.message,
            'image_url': self.image_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'can_delete': True  # Will be set in the route based on user permissions
        }
