"""
Attendance management models for club sessions.
"""
from datetime import datetime, timezone
from extensions import db


class AttendanceSession(db.Model):
    """Represents a club meeting/session where attendance is tracked"""
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    session_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time)
    end_time = db.Column(db.Time)
    location = db.Column(db.String(255))
    session_type = db.Column(db.String(50), default='meeting')
    max_attendance = db.Column(db.Integer)
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref=db.backref('attendance_sessions', lazy='dynamic', cascade='all, delete-orphan'))
    creator = db.relationship('User', backref='created_attendance_sessions')
    attendances = db.relationship('AttendanceRecord', back_populates='session', cascade='all, delete-orphan')

    def get_attendance_count(self):
        return AttendanceRecord.query.filter_by(session_id=self.id, status='present').count()

    def get_guest_count(self):
        return AttendanceGuest.query.filter_by(session_id=self.id).count()

    def to_dict(self):
        return {
            'id': self.id,
            'club_id': self.club_id,
            'title': self.title,
            'description': self.description,
            'session_date': self.session_date.isoformat() if self.session_date else None,
            'start_time': self.start_time.strftime('%H:%M') if self.start_time else None,
            'end_time': self.end_time.strftime('%H:%M') if self.end_time else None,
            'location': self.location,
            'session_type': self.session_type,
            'max_attendance': self.max_attendance,
            'notes': self.notes,
            'is_active': self.is_active,
            'attendance_count': self.get_attendance_count(),
            'guest_count': self.get_guest_count(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AttendanceRecord(db.Model):
    """Tracks individual member attendance at sessions"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('attendance_session.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='present')
    check_in_time = db.Column(db.DateTime)
    check_out_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    marked_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    session = db.relationship('AttendanceSession', back_populates='attendances')
    user = db.relationship('User', foreign_keys=[user_id], backref='attendance_records')
    marker = db.relationship('User', foreign_keys=[marked_by], backref='marked_attendances')

    __table_args__ = (
        db.UniqueConstraint('session_id', 'user_id', name='unique_session_user_attendance'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'user_email': self.user.email if self.user else None,
            'status': self.status,
            'check_in_time': self.check_in_time.isoformat() if self.check_in_time else None,
            'check_out_time': self.check_out_time.isoformat() if self.check_out_time else None,
            'notes': self.notes,
            'marked_by': self.marked_by,
            'marker_username': self.marker.username if self.marker else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AttendanceGuest(db.Model):
    """Tracks guest attendance at sessions"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('attendance_session.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255))
    phone = db.Column(db.String(20))
    organization = db.Column(db.String(100))
    check_in_time = db.Column(db.DateTime)
    check_out_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    session = db.relationship('AttendanceSession', backref=db.backref('guests', cascade='all, delete-orphan'))
    adder = db.relationship('User', backref='added_guests')

    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'organization': self.organization,
            'check_in_time': self.check_in_time.isoformat() if self.check_in_time else None,
            'check_out_time': self.check_out_time.isoformat() if self.check_out_time else None,
            'notes': self.notes,
            'added_by': self.added_by,
            'added_by_username': self.adder.username if self.adder else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
