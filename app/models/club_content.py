"""
Club content models for posts, assignments, meetings, resources, and projects.
"""
from datetime import datetime, timezone
from extensions import db


class ClubPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Stores markdown content
    content_html = db.Column(db.Text)  # Stores rendered HTML content
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref=db.backref('posts', cascade='all, delete-orphan'))
    user = db.relationship('User', backref='posts')


class ClubAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime)
    for_all_members = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref=db.backref('assignments', cascade='all, delete-orphan'))


class ClubMeeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    meeting_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(10), nullable=False)
    end_time = db.Column(db.String(10))
    location = db.Column(db.String(255))
    meeting_link = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref=db.backref('meetings', cascade='all, delete-orphan'))


class ClubResource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='book')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref=db.backref('resources', cascade='all, delete-orphan'))


class ClubProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500))
    github_url = db.Column(db.String(500))
    featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref=db.backref('projects', cascade='all, delete-orphan'))
    user = db.relationship('User', backref='projects')
