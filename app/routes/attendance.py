"""
Attendance routes blueprint for the Hack Club Dashboard.
Handles attendance session management, tracking, and reporting.
"""

from flask import Blueprint, jsonify, request, send_file
from datetime import datetime, timezone
from io import StringIO, BytesIO
import csv
from extensions import db, limiter
from app.decorators.auth import login_required
from app.utils.auth_helpers import get_current_user
from app.utils.club_helpers import verify_club_leadership
from app.utils.sanitization import sanitize_string
from app.models.club import Club, ClubMembership
from app.models.attendance import AttendanceSession, AttendanceRecord, AttendanceGuest
from app.models.user import User

attendance_bp = Blueprint('attendance', __name__)


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/sessions', methods=['GET', 'POST'])
@login_required
@limiter.limit("60 per minute")
def attendance_sessions(club_id):
    """Get or create attendance sessions"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can manage attendance sessions'}), 403

    if request.method == 'GET':
        sessions = AttendanceSession.query.filter_by(
            club_id=club_id
        ).order_by(AttendanceSession.session_date.desc()).all()

        sessions_data = []
        for session in sessions:
            sessions_data.append({
                'id': session.id,
                'title': session.title,
                'session_date': session.session_date.isoformat() if session.session_date else None,
                'location': session.location,
                'notes': session.notes,
                'is_active': session.is_active,
                'created_by': session.created_by,
                'created_at': session.created_at.isoformat() if session.created_at else None
            })

        return jsonify({
            'success': True,
            'sessions': sessions_data,
            'total': len(sessions_data)
        })

    elif request.method == 'POST':
        data = request.get_json()

        title = sanitize_string(data.get('title', ''), max_length=200)
        session_date_str = data.get('session_date')
        location = sanitize_string(data.get('location', ''), max_length=200)
        notes = sanitize_string(data.get('notes', ''), max_length=1000)

        if not title:
            return jsonify({'error': 'Session title is required'}), 400

        if session_date_str:
            try:
                session_date = datetime.fromisoformat(session_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'error': 'Invalid date format'}), 400
        else:
            session_date = datetime.now(timezone.utc)

        session = AttendanceSession(
            club_id=club_id,
            title=title,
            session_date=session_date,
            location=location,
            notes=notes,
            is_active=True,
            created_by=user.id
        )

        db.session.add(session)
        db.session.commit()

        return jsonify({
            'success': True,
            'session': {
                'id': session.id,
                'title': session.title,
                'session_date': session.session_date.isoformat() if session.session_date else None,
                'location': session.location,
                'notes': session.notes,
                'is_active': session.is_active
            }
        }), 201


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@limiter.limit("60 per minute")
def attendance_session_operations(club_id, session_id):
    """Get, update, or delete an attendance session"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can manage attendance sessions'}), 403

    session = AttendanceSession.query.filter_by(
        id=session_id,
        club_id=club_id
    ).first_or_404()

    if request.method == 'GET':
        records = AttendanceRecord.query.filter_by(session_id=session_id).all()
        guests = AttendanceGuest.query.filter_by(session_id=session_id).all()

        records_data = []
        for record in records:
            records_data.append({
                'id': record.id,
                'user_id': record.user_id,
                'username': record.user.username if record.user else None,
                'first_name': record.user.first_name if record.user else None,
                'last_name': record.user.last_name if record.user else None,
                'checked_in_at': record.checked_in_at.isoformat() if record.checked_in_at else None
            })

        guests_data = []
        for guest in guests:
            guests_data.append({
                'id': guest.id,
                'name': guest.name,
                'email': guest.email,
                'checked_in_at': guest.checked_in_at.isoformat() if guest.checked_in_at else None
            })

        return jsonify({
            'success': True,
            'session': {
                'id': session.id,
                'title': session.title,
                'session_date': session.session_date.isoformat() if session.session_date else None,
                'location': session.location,
                'notes': session.notes,
                'is_active': session.is_active
            },
            'members': records_data,
            'guests': guests_data,
            'total_attendance': len(records_data) + len(guests_data)
        })

    elif request.method == 'PUT':
        data = request.get_json()

        if 'title' in data:
            session.title = sanitize_string(data['title'], max_length=200)
        if 'session_date' in data:
            try:
                session.session_date = datetime.fromisoformat(data['session_date'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'error': 'Invalid date format'}), 400
        if 'location' in data:
            session.location = sanitize_string(data['location'], max_length=200)
        if 'notes' in data:
            session.notes = sanitize_string(data['notes'], max_length=1000)
        if 'is_active' in data:
            session.is_active = bool(data['is_active'])

        db.session.commit()

        return jsonify({
            'success': True,
            'session': {
                'id': session.id,
                'title': session.title,
                'session_date': session.session_date.isoformat() if session.session_date else None,
                'location': session.location,
                'notes': session.notes,
                'is_active': session.is_active
            }
        })

    elif request.method == 'DELETE':
        db.session.delete(session)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Session deleted'
        })


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/attendance', methods=['POST'])
@login_required
@limiter.limit("100 per minute")
def mark_attendance(club_id, session_id):
    """Mark attendance for a member"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    membership = ClubMembership.query.filter_by(
        club_id=club_id,
        user_id=user.id
    ).first()

    if not membership:
        return jsonify({'error': 'Not a member of this club'}), 403

    session = AttendanceSession.query.filter_by(
        id=session_id,
        club_id=club_id
    ).first_or_404()

    data = request.get_json()
    user_id_to_mark = data.get('user_id', user.id)

    is_leader = (user.id == session.club.leader_id or user.id == session.club.co_leader_id)
    if user_id_to_mark != user.id and not is_leader and not user.is_admin:
        return jsonify({'error': 'Only leaders can mark attendance for others'}), 403

    existing_record = AttendanceRecord.query.filter_by(
        session_id=session_id,
        user_id=user_id_to_mark
    ).first()

    if existing_record:
        return jsonify({'error': 'Attendance already marked'}), 400

    record = AttendanceRecord(
        session_id=session_id,
        user_id=user_id_to_mark,
        checked_in_at=datetime.now(timezone.utc),
        checked_in_by=user.id
    )

    db.session.add(record)
    db.session.commit()

    marked_user = User.query.get(user_id_to_mark)

    return jsonify({
        'success': True,
        'record': {
            'id': record.id,
            'user_id': record.user_id,
            'username': marked_user.username if marked_user else None,
            'checked_in_at': record.checked_in_at.isoformat() if record.checked_in_at else None
        }
    }), 201


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/guests', methods=['POST'])
@login_required
@limiter.limit("60 per minute")
def add_guest(club_id, session_id):
    """Add a guest to attendance"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can add guests'}), 403

    session = AttendanceSession.query.filter_by(
        id=session_id,
        club_id=club_id
    ).first_or_404()

    data = request.get_json()
    guest_name = sanitize_string(data.get('name', ''), max_length=100)
    guest_email = sanitize_string(data.get('email', ''), max_length=120)

    if not guest_name:
        return jsonify({'error': 'Guest name is required'}), 400

    guest = AttendanceGuest(
        session_id=session_id,
        name=guest_name,
        email=guest_email,
        checked_in_at=datetime.now(timezone.utc),
        added_by=user.id
    )

    db.session.add(guest)
    db.session.commit()

    return jsonify({
        'success': True,
        'guest': {
            'id': guest.id,
            'name': guest.name,
            'email': guest.email,
            'checked_in_at': guest.checked_in_at.isoformat() if guest.checked_in_at else None
        }
    }), 201


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/records/<int:record_id>', methods=['DELETE'])
@login_required
def delete_attendance_record(club_id, record_id):
    """Delete an attendance record"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can delete attendance records'}), 403

    record = AttendanceRecord.query.get_or_404(record_id)

    if record.session.club_id != club_id:
        return jsonify({'error': 'Record not found in this club'}), 404

    db.session.delete(record)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Attendance record deleted'
    })


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/guests/<int:guest_id>', methods=['DELETE'])
@login_required
def delete_guest(club_id, guest_id):
    """Delete a guest record"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can delete guests'}), 403

    guest = AttendanceGuest.query.get_or_404(guest_id)

    if guest.session.club_id != club_id:
        return jsonify({'error': 'Guest not found in this club'}), 404

    db.session.delete(guest)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Guest deleted'
    })


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/reports', methods=['GET'])
@login_required
def attendance_reports(club_id):
    """Get attendance reports for a club"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can view reports'}), 403

    sessions = AttendanceSession.query.filter_by(club_id=club_id).all()

    total_sessions = len(sessions)
    total_attendees = 0
    member_attendance = {}

    for session in sessions:
        records = AttendanceRecord.query.filter_by(session_id=session.id).all()
        total_attendees += len(records)

        for record in records:
            if record.user_id not in member_attendance:
                member_attendance[record.user_id] = {
                    'user': record.user,
                    'sessions_attended': 0
                }
            member_attendance[record.user_id]['sessions_attended'] += 1

    members_data = []
    for user_id, data in member_attendance.items():
        user_obj = data['user']
        members_data.append({
            'user_id': user_id,
            'username': user_obj.username,
            'first_name': user_obj.first_name,
            'last_name': user_obj.last_name,
            'sessions_attended': data['sessions_attended'],
            'attendance_rate': (data['sessions_attended'] / total_sessions * 100) if total_sessions > 0 else 0
        })

    members_data.sort(key=lambda x: x['sessions_attended'], reverse=True)

    return jsonify({
        'success': True,
        'total_sessions': total_sessions,
        'average_attendance': total_attendees / total_sessions if total_sessions > 0 else 0,
        'members': members_data
    })


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/export', methods=['GET'])
@login_required
def export_attendance(club_id):
    """Export attendance data as CSV"""
    user = get_current_user()
    club = Club.query.get_or_404(club_id)

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can export attendance'}), 403

    sessions = AttendanceSession.query.filter_by(club_id=club_id).order_by(
        AttendanceSession.session_date.desc()
    ).all()

    def sanitize_csv_cell(value):
        """Prevent CSV formula injection by escaping dangerous characters"""
        if not value:
            return ''
        value_str = str(value)
        if value_str and value_str[0] in ('=', '+', '-', '@', '\t', '\r'):
            return "'" + value_str
        return value_str

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(['Session Date', 'Session Title', 'Attendee Name', 'Attendee Email', 'Type', 'Checked In At'])

    for session in sessions:
        records = AttendanceRecord.query.filter_by(session_id=session.id).all()
        for record in records:
            writer.writerow([
                session.session_date.strftime('%Y-%m-%d') if session.session_date else '',
                sanitize_csv_cell(session.title),
                sanitize_csv_cell(f"{record.user.first_name} {record.user.last_name}".strip() or record.user.username),
                sanitize_csv_cell(record.user.email),
                'Member',
                record.checked_in_at.strftime('%Y-%m-%d %H:%M:%S') if record.checked_in_at else ''
            ])

        guests = AttendanceGuest.query.filter_by(session_id=session.id).all()
        for guest in guests:
            writer.writerow([
                session.session_date.strftime('%Y-%m-%d') if session.session_date else '',
                sanitize_csv_cell(session.title),
                sanitize_csv_cell(guest.name),
                sanitize_csv_cell(guest.email or ''),
                'Guest',
                guest.checked_in_at.strftime('%Y-%m-%d %H:%M:%S') if guest.checked_in_at else ''
            ])

    output.seek(0)
    csv_data = output.getvalue().encode('utf-8')
    output_bytes = BytesIO(csv_data)

    filename = f"attendance_{club.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.csv"

    return send_file(
        output_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


@attendance_bp.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/notes', methods=['POST'])
@login_required
def update_session_notes(club_id, session_id):
    """Update notes for an attendance session"""
    from app.models.user import create_audit_log
    from app.utils.sanitization import sanitize_string

    user = get_current_user()
    club = Club.query.get_or_404(club_id)
    session = AttendanceSession.query.get_or_404(session_id)

    if session.club_id != club_id:
        return jsonify({'error': 'Session not found in this club'}), 404

    if not verify_club_leadership(club, user):
        return jsonify({'error': 'Only club leaders can update session notes'}), 403

    data = request.get_json()
    notes = sanitize_string(data.get('notes', ''), max_length=5000)

    session.notes = notes
    db.session.commit()

    create_audit_log(
        action_type='attendance_session_notes_update',
        description=f'Updated notes for attendance session in {club.name}',
        user=user,
        target_type='attendance_session',
        target_id=session_id,
        category='club'
    )

    return jsonify({
        'success': True,
        'message': 'Session notes updated successfully',
        'notes': notes
    })
