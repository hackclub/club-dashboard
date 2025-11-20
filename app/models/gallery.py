"""
Gallery models for club photo posts.
"""
import json
from datetime import datetime, timezone
from extensions import db


class GalleryPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    images = db.Column(db.Text)  # JSON array of image URLs
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    featured = db.Column(db.Boolean, default=False)

    club = db.relationship('Club', backref=db.backref('gallery_posts', cascade='all, delete-orphan'))
    user = db.relationship('User', backref='gallery_posts')

    def get_images(self):
        """Get parsed images as a list"""
        try:
            return json.loads(self.images) if self.images else []
        except:
            return []

    def set_images(self, images_list):
        """Set images as JSON"""
        self.images = json.dumps(images_list)
