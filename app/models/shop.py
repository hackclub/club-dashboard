"""
Shop and Order models for the Hack Club Dashboard.
Handles shop items and order management.
"""

from datetime import datetime
from extensions import db


class ShopItem(db.Model):
    """Shop item model"""
    __tablename__ = 'shop_items'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Integer, nullable=False, default=0)  # Price in tokens
    image_url = db.Column(db.String(500))
    category = db.Column(db.String(100))
    stock = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    orders = db.relationship('Order', backref='shop_item', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'image_url': self.image_url,
            'category': self.category,
            'stock': self.stock,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class Order(db.Model):
    """Order model"""
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('clubs.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shop_item_id = db.Column(db.Integer, db.ForeignKey('shop_items.id'))

    status = db.Column(db.String(50), default='pending')  # pending, approved, rejected, completed, refunded
    quantity = db.Column(db.Integer, default=1)
    total_price = db.Column(db.Integer, nullable=False)

    shipping_name = db.Column(db.String(200))
    shipping_address = db.Column(db.Text)
    shipping_city = db.Column(db.String(100))
    shipping_state = db.Column(db.String(100))
    shipping_zip = db.Column(db.String(20))
    shipping_country = db.Column(db.String(100))

    notes = db.Column(db.Text)
    admin_notes = db.Column(db.Text)
    tracking_number = db.Column(db.String(200))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)


    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'club_id': self.club_id,
            'club_name': self.club.name if self.club else 'Unknown',
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'Unknown',
            'shop_item_id': self.shop_item_id,
            'shop_item_name': self.shop_item.name if self.shop_item else 'Custom Order',
            'status': self.status,
            'quantity': self.quantity,
            'total_price': self.total_price,
            'shipping_name': self.shipping_name,
            'shipping_address': self.shipping_address,
            'shipping_city': self.shipping_city,
            'shipping_state': self.shipping_state,
            'shipping_zip': self.shipping_zip,
            'shipping_country': self.shipping_country,
            'notes': self.notes,
            'admin_notes': self.admin_notes,
            'tracking_number': self.tracking_number,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
