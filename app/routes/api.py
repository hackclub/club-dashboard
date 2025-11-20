"""
API routes blueprint for the Hack Club Dashboard.
Handles public API endpoints, admin API, and mobile app endpoints.
"""

import html
import logging
import requests as http_requests
from flask import Blueprint, jsonify, request, current_app, session
from extensions import db, limiter
from app.decorators.auth import api_key_required, oauth_required, admin_required, login_required, reviewer_required, permission_required

logger = logging.getLogger(__name__)
from app.utils.auth_helpers import get_current_user, is_authenticated
from app.utils.club_helpers import is_user_co_leader
from app.utils.sanitization import sanitize_string
from app.utils.formatting import markdown_to_html
from app.utils.security import validate_input_with_security, validate_password
from app.utils.economy_helpers import create_club_transaction, update_quest_progress
from app.models.user import User, create_audit_log
from app.models.club import Club, ClubMembership
from app.models.club_content import ClubPost, ClubAssignment, ClubMeeting, ClubProject
from app.models.gallery import GalleryPost
from app.models.economy import ClubTransaction, ClubQuestProgress
from app.models.system import SystemSettings
from app.services.airtable import airtable_service

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/docs')
def api_documentation():
    """API documentation page"""
    from flask import render_template
    return render_template('api_docs.html')
@api_bp.route('/user', methods=['GET'])
@oauth_required(scopes=['user:read'])
def get_user():
    """Get current user information (OAuth)"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'created_at': user.created_at.isoformat() if user.created_at else None
    })


@api_bp.route('/user/clubs', methods=['GET'])
@oauth_required(scopes=['clubs:read'])
def get_user_clubs():
    """Get user's clubs (OAuth)"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    memberships = ClubMembership.query.filter_by(user_id=user.id).all()

    clubs_data = []
    for membership in memberships:
        club = membership.club
        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'tokens': club.tokens,
            'is_leader': user.id == club.leader_id,
            'is_co_leader': user.id == club.co_leader_id,
            'joined_at': membership.joined_at.isoformat() if membership.joined_at else None
        })

    return jsonify({
        'clubs': clubs_data,
        'total': len(clubs_data)
    })


@api_bp.route('/user/assignments', methods=['GET'])
@oauth_required(scopes=['assignments:read'])
def get_user_assignments():
    """Get user's club assignments (OAuth)"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    memberships = ClubMembership.query.filter_by(user_id=user.id).all()
    club_ids = [m.club_id for m in memberships]

    assignments = ClubAssignment.query.filter(
        ClubAssignment.club_id.in_(club_ids)
    ).order_by(ClubAssignment.due_date.desc()).all()

    assignments_data = []
    for assignment in assignments:
        assignments_data.append({
            'id': assignment.id,
            'club_id': assignment.club_id,
            'club_name': assignment.club.name,
            'title': assignment.title,
            'description': assignment.description,
            'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
            'created_at': assignment.created_at.isoformat() if assignment.created_at else None
        })

    return jsonify({
        'assignments': assignments_data,
        'total': len(assignments_data)
    })


@api_bp.route('/user/meetings', methods=['GET'])
@oauth_required(scopes=['meetings:read'])
def get_user_meetings():
    """Get user's club meetings (OAuth)"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    memberships = ClubMembership.query.filter_by(user_id=user.id).all()
    club_ids = [m.club_id for m in memberships]

    meetings = ClubMeeting.query.filter(
        ClubMeeting.club_id.in_(club_ids)
    ).order_by(ClubMeeting.meeting_date.desc()).all()

    meetings_data = []
    for meeting in meetings:
        meetings_data.append({
            'id': meeting.id,
            'club_id': meeting.club_id,
            'club_name': meeting.club.name,
            'title': meeting.title,
            'description': meeting.description,
            'meeting_date': meeting.meeting_date.isoformat() if meeting.meeting_date else None,
            'location': meeting.location,
            'created_at': meeting.created_at.isoformat() if meeting.created_at else None
        })

    return jsonify({
        'meetings': meetings_data,
        'total': len(meetings_data)
    })


@api_bp.route('/user/projects', methods=['GET'])
@oauth_required(scopes=['projects:read'])
def get_user_projects():
    """Get user's club projects (OAuth)"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    memberships = ClubMembership.query.filter_by(user_id=user.id).all()
    club_ids = [m.club_id for m in memberships]

    projects = ClubProject.query.filter(
        ClubProject.club_id.in_(club_ids)
    ).order_by(ClubProject.created_at.desc()).all()

    projects_data = []
    for project in projects:
        projects_data.append({
            'id': project.id,
            'club_id': project.club_id,
            'club_name': project.club.name,
            'name': project.name,
            'description': project.description,
            'url': project.url,
            'created_at': project.created_at.isoformat() if project.created_at else None
        })

    return jsonify({
        'projects': projects_data,
        'total': len(projects_data)
    })
@api_bp.route('/admin/users', methods=['GET'])
@login_required
@permission_required('users.view')
@limiter.limit("100 per minute")
def admin_get_users():
    """Get all users (admin only)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    per_page = min(per_page, 100)  # Max 100 per page

    users_pagination = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    users_data = []
    for user in users_pagination.items:
        from app.models.club import Club
        clubs_led = Club.query.filter(
            (Club.leader_id == user.id) | (Club.co_leader_id == user.id)
        ).count()

        from app.models.club import ClubMembership
        clubs_joined = ClubMembership.query.filter_by(user_id=user.id).count()

        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_admin': user.is_admin,
            'is_suspended': user.is_suspended,
            'totp_enabled': user.totp_enabled,
            'clubs_led': clubs_led,
            'clubs_joined': clubs_joined,
            'created_at': user.created_at.isoformat() if user.created_at else None
        })

    return jsonify({
        'users': users_data,
        'total': users_pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': users_pagination.pages
    })


@api_bp.route('/admin/users/<int:user_id>', methods=['GET'])
@login_required
@permission_required('users.view')
@limiter.limit("100 per minute")
def admin_get_user(user_id):
    """Get a specific user by ID (for leadership transfer, etc.)"""
    user = User.query.get_or_404(user_id)

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_admin': user.is_admin,
        'is_suspended': user.is_suspended
    })


@api_bp.route('/admin/users/search', methods=['GET'])
@login_required
@permission_required('users.view')
@limiter.limit("100 per minute")
def admin_search_users():
    """Search users by username or email (for leadership transfer, etc.)"""
    query = request.args.get('q', '').strip()
    limit = request.args.get('limit', 10, type=int)
    limit = min(limit, 50)  # Max 50 results

    if not query:
        return jsonify({'users': []})

    search_term = f"%{query}%"
    users = User.query.filter(
        db.or_(
            User.username.ilike(search_term),
            User.email.ilike(search_term),
            User.first_name.ilike(search_term),
            User.last_name.ilike(search_term)
        )
    ).limit(limit).all()

    users_data = [{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'first_name': u.first_name,
        'last_name': u.last_name,
        'is_admin': u.is_admin,
        'is_suspended': u.is_suspended,
        'avatar_url': '/static/assets/heidi-avatar.png'  # Default avatar for all users
    } for u in users]

    return jsonify({'users': users_data})


@api_bp.route('/admin/clubs', methods=['GET'])
@login_required
@permission_required('clubs.view')
@limiter.limit("100 per minute")
def admin_get_clubs():
    """Get all clubs (admin only) - includes dashboard clubs and Airtable-only clubs"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '').strip().lower()
    per_page = min(per_page, 100)

    # Get dashboard clubs
    query = Club.query

    if search:
        query = query.filter(
            db.or_(
                Club.name.ilike(f'%{search}%'),
                Club.location.ilike(f'%{search}%')
            )
        )

    clubs_pagination = query.order_by(Club.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    clubs_data = []
    dashboard_club_names = set()

    for club in clubs_pagination.items:
        leader_username = club.leader.username if club.leader else 'Unknown'
        leader_email = club.leader.email if club.leader else 'Unknown'

        from app.models.club import ClubMembership
        member_count = ClubMembership.query.filter_by(club_id=club.id).count()

        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'leader': leader_username,
            'leader_email': leader_email,
            'member_count': member_count,
            'location': club.location,
            'tokens': club.tokens,
            'balance': club.balance,
            'created_at': club.created_at.isoformat() if club.created_at else None,
            'is_suspended': club.is_suspended,
            'airtable_id': getattr(club, 'airtable_id', None),
            'is_airtable_only': False
        })
        dashboard_club_names.add(club.name.lower().strip())

    # Get Airtable clubs if searching
    if search:
        try:
            airtable_clubs = airtable_service.get_all_clubs()

            # Filter Airtable clubs by search and exclude already-linked clubs
            for airtable_club in airtable_clubs:
                club_name = airtable_club['name'].lower().strip()

                # Check if this club matches the search and isn't already in dashboard
                if (search in club_name or search in airtable_club['location'].lower()) and \
                   club_name not in dashboard_club_names:

                    clubs_data.append({
                        'id': None,  # No dashboard ID
                        'name': airtable_club['name'],
                        'description': None,
                        'leader': None,
                        'leader_email': airtable_club['leader_emails'],
                        'member_count': None,
                        'location': airtable_club['location'],
                        'tokens': None,
                        'balance': None,
                        'created_at': None,
                        'is_suspended': airtable_club['suspended'],
                        'airtable_id': airtable_club['airtable_id'],
                        'is_airtable_only': True
                    })

        except Exception as e:
            current_app.logger.error(f"Error fetching Airtable clubs: {str(e)}")

    return jsonify({
        'clubs': clubs_data,
        'total': clubs_pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': clubs_pagination.pages
    })


@api_bp.route('/admin/clubs/suspend', methods=['POST'])
@login_required
@permission_required('clubs.suspend')
def suspend_club():
    """Suspend or unsuspend a club (dashboard or Airtable-only)"""
    data = request.get_json()
    club_id = data.get('club_id')  # Dashboard club ID (if exists)
    airtable_id = data.get('airtable_id')  # Airtable record ID
    suspended = data.get('suspended', True)
    is_airtable_only = data.get('is_airtable_only', False)

    current_user = get_current_user()

    try:
        # Handle dashboard clubs
        if club_id and not is_airtable_only:
            club = Club.query.get_or_404(club_id)
            club.is_suspended = suspended
            db.session.commit()

            # Also sync to Airtable if it has an airtable_id
            airtable_data = club.get_airtable_data()
            airtable_club_id = airtable_data.get('airtable_id') if airtable_data else airtable_id
            if airtable_club_id:
                airtable_service.update_club_suspension(airtable_club_id, suspended, club_name=club.name)

            # Log suspension action
            create_audit_log(
                action_type='club_suspended' if suspended else 'club_unsuspended',
                description=f'Admin {current_user.username} {"suspended" if suspended else "unsuspended"} club: {club.name}',
                user=current_user,
                target_type='club',
                target_id=club_id,
                severity='warning' if suspended else 'info',
                category='admin',
                admin_action=True
            )

            return jsonify({
                'success': True,
                'message': f'Club {"suspended" if suspended else "unsuspended"} successfully'
            })

        # Handle Airtable-only clubs
        elif airtable_id and is_airtable_only:
            club_name = data.get('club_name', 'Unknown')
            success = airtable_service.update_club_suspension(airtable_id, suspended, club_name=club_name)

            if success:

                create_audit_log(
                    action_type='airtable_club_suspended' if suspended else 'airtable_club_unsuspended',
                    description=f'Admin {current_user.username} {"suspended" if suspended else "unsuspended"} Airtable club: {club_name}',
                    user=current_user,
                    target_type='airtable_club',
                    target_id=airtable_id,
                    severity='warning' if suspended else 'info',
                    category='admin',
                    admin_action=True,
                    details={'airtable_id': airtable_id}
                )

                return jsonify({
                    'success': True,
                    'message': f'Airtable club {"suspended" if suspended else "unsuspended"} successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Failed to update suspension status in Airtable'
                }), 500
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid club identifiers provided'
            }), 400

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error suspending club: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@api_bp.route('/admin/stats', methods=['GET'])
@login_required
@admin_required
def admin_get_stats():
    """Get system statistics (admin only)"""
    from app.models.economy import ClubTransaction, ProjectSubmission

    stats = {
        'users': {
            'total': User.query.count(),
            'active': User.query.filter_by(is_suspended=False).count(),
            'suspended': User.query.filter_by(is_suspended=True).count(),
            'admins': User.query.filter_by(is_admin=True).count()
        },
        'clubs': {
            'total': Club.query.count(),
            'total_tokens': db.session.query(db.func.sum(Club.tokens)).scalar() or 0
        },
        'projects': {
            'pending': ProjectSubmission.query.filter_by(approved_at=None).count(),
            'approved': ProjectSubmission.query.filter(
                ProjectSubmission.approved_at.isnot(None)
            ).count()
        },
        'transactions': {
            'total': ClubTransaction.query.count(),
            'total_credits': db.session.query(
                db.func.sum(ClubTransaction.amount)
            ).filter(ClubTransaction.amount > 0).scalar() or 0
        }
    }

    return jsonify(stats)


@api_bp.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    """Get/update system settings (admin only)"""
    if request.method == 'GET':
        return jsonify({
            'maintenance_mode': SystemSettings.is_maintenance_mode(),
            'economy_enabled': SystemSettings.is_economy_enabled(),
            'registration_enabled': SystemSettings.is_user_registration_enabled(),
            'mobile_enabled': SystemSettings.is_mobile_enabled(),
            'club_creation_enabled': SystemSettings.is_club_creation_enabled(),
            'announcement': SystemSettings.get_setting('announcement', '')
        })

    elif request.method == 'POST':
        data = request.get_json()
        current_user = get_current_user()

        if 'maintenance_mode' in data:
            SystemSettings.set_setting('maintenance_mode', str(data['maintenance_mode']).lower(), current_user.id)
        if 'economy_enabled' in data:
            SystemSettings.set_setting('economy_enabled', str(data['economy_enabled']).lower(), current_user.id)
        if 'registration_enabled' in data:
            SystemSettings.set_setting('user_registration_enabled', str(data['registration_enabled']).lower(), current_user.id)
        if 'mobile_enabled' in data:
            SystemSettings.set_setting('mobile_enabled', str(data['mobile_enabled']).lower(), current_user.id)
        if 'club_creation_enabled' in data:
            SystemSettings.set_setting('club_creation_enabled', str(data['club_creation_enabled']).lower(), current_user.id)
        if 'announcement' in data:
            SystemSettings.set_setting('announcement', data['announcement'], current_user.id)

        return jsonify({
            'success': True,
            'message': 'Settings updated'
        })


@api_bp.route('/admin/activity', methods=['GET'])
@login_required
@admin_required
@limiter.limit("100 per minute")
def admin_get_activity():
    """Get recent activity (admin only)"""
    from app.models.user import AuditLog

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    per_page = min(per_page, 100)

    logs_pagination = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    logs_data = []
    for log in logs_pagination.items:
        logs_data.append({
            'id': log.id,
            'user_id': log.user_id,
            'action_type': log.action_type,
            'description': log.description,
            'target_type': log.target_type,
            'target_id': log.target_id,
            'severity': log.severity,
            'category': log.action_category,
            'timestamp': log.timestamp.isoformat() if log.timestamp else None
        })

    return jsonify({
        'logs': logs_data,
        'total': logs_pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': logs_pagination.pages
    })


@api_bp.route('/admin/rbac/roles', methods=['GET'])
@login_required
@admin_required
def admin_get_roles():
    """Get all roles (admin only)"""
    from app.models.user import Role
    roles = Role.query.all()
    roles_data = []
    for role in roles:
        roles_data.append({
            'id': role.id,
            'name': role.name,
            'display_name': role.display_name,
            'description': role.description,
            'is_system_role': role.is_system_role,
            'requires_2fa': role.requires_2fa,
            'permissions': [p.name for p in role.permissions.all()],
            'user_count': len(role.users)
        })
    return jsonify({'roles': roles_data})


@api_bp.route('/admin/rbac/permissions', methods=['GET'])
@login_required
@admin_required
def admin_get_permissions():
    """Get all permissions (admin only)"""
    from app.models.user import Permission
    permissions = Permission.query.all()

    permissions_by_category = {}
    for perm in permissions:
        if perm.category not in permissions_by_category:
            permissions_by_category[perm.category] = []
        permissions_by_category[perm.category].append({
            'id': perm.id,
            'name': perm.name,
            'display_name': perm.display_name,
            'description': perm.description,
            'category': perm.category
        })

    return jsonify({'permissions': permissions_by_category})


@api_bp.route('/admin/rbac/users/<int:user_id>/roles', methods=['GET'])
@login_required
@permission_required('users.view', 'system.manage_roles')
def admin_get_user_roles(user_id):
    """Get a specific user's roles and permissions (admin only)"""
    try:
        from app.models.user import User, UserRole

        user = User.query.get_or_404(user_id)

        user_roles = UserRole.query.filter_by(user_id=user_id).all()
        roles_data = []
        permissions_data = []

        for user_role in user_roles:
            role = user_role.role
            roles_data.append({
                'id': role.id,
                'name': role.name,
                'display_name': role.display_name,
                'description': role.description
            })

            try:
                for perm in role.permissions.all():
                    if perm.name not in [p['name'] for p in permissions_data]:
                        permissions_data.append({
                            'id': perm.id,
                            'name': perm.name,
                            'display_name': perm.display_name,
                            'category': perm.category
                        })
            except Exception:
                pass

        return jsonify({
            'roles': roles_data,
            'permissions': permissions_data,
            'is_root': user.is_root if hasattr(user, 'is_root') else False
        })
    except Exception as e:
        return jsonify({
            'roles': [],
            'permissions': [],
            'is_root': False
        })




@api_bp.route('/admin/audit-logs', methods=['GET'])
@login_required
@admin_required
def admin_get_audit_logs():
    """Get audit logs (admin only)"""
    from app.models.user import AuditLog

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    per_page = min(per_page, 100)

    logs_pagination = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    logs_data = []
    for log in logs_pagination.items:
        logs_data.append({
            'id': log.id,
            'user_id': log.user_id,
            'username': log.user.username if log.user else 'System',
            'action_type': log.action_type,
            'description': log.description,
            'target_type': log.target_type,
            'target_id': log.target_id,
            'severity': log.severity,
            'action_category': log.action_category,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat() if log.timestamp else None
        })

    return jsonify({
        'logs': logs_data,
        'total': logs_pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': logs_pagination.pages
    })
@api_bp.route('/admin/users/<int:user_id>', methods=['PUT'])
@login_required
@permission_required('users.edit')
def admin_update_user(user_id):
    """Update user details (requires users.edit permission)"""
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    data = request.get_json()

    if user.is_root_user() and current_user.id != user.id:
        return jsonify({'error': 'Cannot modify root user'}), 403

    if 'username' in data:
        username = sanitize_string(data['username'], max_length=80)
        if username != user.username:
            existing = User.query.filter_by(username=username).first()
            if existing:
                return jsonify({'error': 'Username already exists'}), 400
            user.username = username

    if 'email' in data:
        email = sanitize_string(data['email'], max_length=120)
        if email != user.email:
            existing = User.query.filter_by(email=email).first()
            if existing:
                return jsonify({'error': 'Email already exists'}), 400
            user.email = email

    if 'first_name' in data:
        user.first_name = sanitize_string(data['first_name'], max_length=50)

    if 'last_name' in data:
        user.last_name = sanitize_string(data['last_name'], max_length=50)

    db.session.commit()

    create_audit_log(
        action_type='user_update',
        description=f'Admin {current_user.username} updated user {user.username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        details={'updated_fields': list(data.keys())},
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'User updated successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
    })


@api_bp.route('/api/admin/users/create', methods=['POST'])
@login_required
@permission_required('users.create')
def admin_create_user():
    """Create a single user (requires users.create permission)"""
    import secrets
    
    current_user = get_current_user()
    data = request.get_json()
    
    username = sanitize_string(data.get('username', ''), max_length=80).strip()
    email = sanitize_string(data.get('email', ''), max_length=120).strip()
    first_name = sanitize_string(data.get('first_name', ''), max_length=50).strip()
    last_name = sanitize_string(data.get('last_name', ''), max_length=50).strip()
    password = data.get('password', '').strip()
    
    if not username or not email:
        return jsonify({'error': 'Username and email are required'}), 400
    
    if not password:
        password = secrets.token_urlsafe(12)
    elif len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Check if username or email already exists
    if User.query.filter_by(username=username).first():
        return jsonify({'error': f'Username "{username}" already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': f'Email "{email}" already exists'}), 400
    
    try:
        # Create the user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        create_audit_log(
            action_type='user_created',
            description=f'Admin {current_user.username} created user {username}',
            user=current_user,
            target_type='user',
            target_id=user.id,
            admin_action=True,
            category='admin'
        )
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating user: {str(e)}")
        return jsonify({'error': 'Failed to create user'}), 500


@api_bp.route('/api/admin/users/bulk-create', methods=['POST'])
@login_required
@permission_required('users.create')
def admin_bulk_create_users():
    """Bulk create users from CSV data (requires users.create permission)"""
    import secrets
    import csv
    from io import StringIO
    
    current_user = get_current_user()
    data = request.get_json()
    csv_data = data.get('csv_data', [])
    
    if not csv_data or len(csv_data) < 2:
        return jsonify({'error': 'Invalid CSV data'}), 400
    
    created = 0
    failed = 0
    errors = []
    
    try:
        # Parse CSV
        csv_text = '\n'.join(csv_data)
        csv_file = StringIO(csv_text)
        reader = csv.DictReader(csv_file)
        
        for row_num, row in enumerate(reader, start=2):  # Start at 2 to account for header
            try:
                username = sanitize_string(row.get('username', ''), max_length=80).strip()
                email = sanitize_string(row.get('email', ''), max_length=120).strip()
                first_name = sanitize_string(row.get('first_name', ''), max_length=50).strip()
                last_name = sanitize_string(row.get('last_name', ''), max_length=50).strip()
                password = row.get('password', '').strip()
                
                if not username or not email:
                    errors.append(f'Row {row_num}: Username and email are required')
                    failed += 1
                    continue
                
                # Check if user already exists
                if User.query.filter_by(username=username).first():
                    errors.append(f'Row {row_num}: Username "{username}" already exists')
                    failed += 1
                    continue
                
                if User.query.filter_by(email=email).first():
                    errors.append(f'Row {row_num}: Email "{email}" already exists')
                    failed += 1
                    continue
                
                # Generate password if not provided
                if not password:
                    password = secrets.token_urlsafe(12)
                elif len(password) < 6:
                    errors.append(f'Row {row_num}: Password must be at least 6 characters')
                    failed += 1
                    continue
                
                # Create user
                user = User(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name
                )
                user.set_password(password)
                
                db.session.add(user)
                created += 1
                
            except Exception as e:
                errors.append(f'Row {row_num}: {str(e)}')
                failed += 1
                continue
        
        db.session.commit()
        
        create_audit_log(
            action_type='users_bulk_created',
            description=f'Admin {current_user.username} bulk created {created} users',
            user=current_user,
            details={'created': created, 'failed': failed},
            admin_action=True,
            category='admin'
        )
        
        return jsonify({
            'success': True,
            'message': f'Created {created} users, {failed} failed',
            'created': created,
            'failed': failed,
            'errors': errors[:10]  # Limit to first 10 errors
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error bulk creating users: {str(e)}")
        return jsonify({'error': f'Failed to process CSV: {str(e)}'}), 500


@api_bp.route('/admin/users/<int:user_id>/suspend', methods=['PUT'])
@login_required
@permission_required('users.suspend')
def admin_suspend_user(user_id):
    """Suspend/unsuspend a user (admin only)"""
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if user.is_root_user():
        return jsonify({'error': 'Cannot suspend root user'}), 403

    data = request.get_json()
    suspend = data.get('suspended', True)
    reason = sanitize_string(data.get('reason', ''), max_length=500)

    user.is_suspended = suspend
    db.session.commit()

    action = 'suspended' if suspend else 'unsuspended'
    create_audit_log(
        action_type=f'user_{action}',
        description=f'Admin {current_user.username} {action} user {user.username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        details={'reason': reason},
        severity='warning' if suspend else 'info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': f'User {action} successfully',
        'suspended': user.is_suspended
    })


@api_bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@permission_required('users.delete')
def admin_delete_user(user_id):
    """Delete a user (admin only)"""
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if user.is_root_user():
        return jsonify({'error': 'Cannot delete root user'}), 403

    username = user.username
    email = user.email

    with db.session.no_autoflush:
        # Handle clubs where user is leader - delete the clubs
        led_clubs = Club.query.filter_by(leader_id=user_id).all()
        for club in led_clubs:
            db.session.delete(club)
        
        # Handle clubs where user is co-leader - remove co-leader
        co_led_clubs = Club.query.filter_by(co_leader_id=user_id).all()
        for club in co_led_clubs:
            club.co_leader_id = None

        db.session.delete(user)
    
    db.session.commit()

    create_audit_log(
        action_type='user_delete',
        description=f'Admin {current_user.username} deleted user {username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        details={'username': username, 'email': email},
        severity='warning',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'User deleted successfully'
    })


@api_bp.route('/admin/users/<int:user_id>/remove-2fa', methods=['POST'])
@login_required
@permission_required('users.manage_2fa')
def admin_remove_2fa(user_id):
    """Remove 2FA from a user account (admin only)"""
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if not user.totp_enabled:
        return jsonify({'error': 'User does not have 2FA enabled'}), 400

    # Store username before disabling
    username = user.username

    # Disable 2FA
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_backup_codes = None
    user.totp_enabled_at = None

    db.session.commit()

    create_audit_log(
        action_type='admin_2fa_remove',
        description=f'Admin {current_user.username} removed 2FA for user {username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        details={'username': username, 'reason': 'admin_removal'},
        severity='warning',
        admin_action=True,
        category='security'
    )

    return jsonify({
        'success': True,
        'message': f'2FA has been removed for {username}'
    })


@api_bp.route('/admin/users/group-by-ip', methods=['GET'])
@login_required
@admin_required
def admin_get_users_by_ip():
    """Get users grouped by IP address (admin only)"""
    users = User.query.all()

    ip_groups = {}
    for user in users:
        ips = user.get_all_ips()
        for ip in ips:
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_suspended': user.is_suspended,
                'created_at': user.created_at.isoformat() if user.created_at else None
            })

    sorted_groups = sorted(
        [{'ip': ip, 'users': users, 'count': len(users)}
         for ip, users in ip_groups.items()],
        key=lambda x: x['count'],
        reverse=True
    )

    return jsonify({'ip_groups': sorted_groups})


@api_bp.route('/admin/users/group-by-club', methods=['GET'])
@login_required
@admin_required
def admin_get_users_by_club():
    """Get users grouped by club (admin only)"""
    from app.models.club import ClubMembership

    clubs = Club.query.all()
    club_groups = []

    for club in clubs:
        memberships = ClubMembership.query.filter_by(club_id=club.id).all()
        members = []
        for membership in memberships:
            user = membership.user
            members.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_leader': club.leader_id == user.id,
                'is_co_leader': club.co_leader_id == user.id,
                'joined_at': membership.joined_at.isoformat() if membership.joined_at else None
            })

        club_groups.append({
            'club_id': club.id,
            'club_name': club.name,
            'member_count': len(members),
            'members': members
        })

    return jsonify({'club_groups': club_groups})


@api_bp.route('/admin/users/<int:user_id>/ips', methods=['GET'])
@login_required
@admin_required
def admin_get_user_ips(user_id):
    """Get IP history for a user (admin only)"""
    user = User.query.get_or_404(user_id)

    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'registration_ip': user.registration_ip,
        'last_login_ip': user.last_login_ip,
        'all_ips': user.get_all_ips()
    })


@api_bp.route('/admin/login-as-user/<int:user_id>', methods=['POST'])
@login_required
@permission_required('users.impersonate', 'admin.login_as_user')
def admin_login_as_user(user_id):
    """Login as another user (admin only)"""
    from flask import session

    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if user.is_root_user():
        return jsonify({'error': 'Cannot impersonate root user'}), 403

    if 'original_user_id' not in session:
        session['original_user_id'] = current_user.id

    session['user_id'] = user.id

    create_audit_log(
        action_type='admin_impersonate',
        description=f'Admin {current_user.username} logged in as {user.username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        severity='warning',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': f'Now logged in as {user.username}',
        'redirect': '/dashboard'
    })


@api_bp.route('/admin/reset-password/<int:user_id>', methods=['POST'])
@login_required
@permission_required('users.edit')
def admin_reset_password(user_id):
    """Reset a user's password (admin only)"""
    import secrets

    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if user.is_root_user() and current_user.id != user.id:
        return jsonify({'error': 'Cannot reset root user password'}), 403

    new_password = secrets.token_urlsafe(16)
    user.set_password(new_password)
    db.session.commit()

    create_audit_log(
        action_type='password_reset',
        description=f'Admin {current_user.username} reset password for {user.username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        severity='warning',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'Password reset successfully',
        'new_password': new_password,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        }
    })


@api_bp.route('/admin/clubs/<int:club_id>', methods=['PUT'])
@login_required
@permission_required('clubs.edit')
def admin_update_club(club_id):
    """Update club details (requires clubs.edit permission)"""
    from app.services.airtable import AirtableService
    from datetime import datetime, timezone
    
    club = Club.query.get_or_404(club_id)
    current_user = get_current_user()

    data = request.get_json()

    # Track what changed for Airtable sync
    old_name = club.name
    changes = {}

    if 'name' in data:
        club.name = sanitize_string(data['name'], max_length=100)
        changes['name'] = club.name

    if 'description' in data:
        club.description = sanitize_string(data['description'], max_length=1000)
        changes['description'] = club.description

    if 'location' in data:
        club.location = sanitize_string(data['location'], max_length=200)
        changes['location'] = club.location

    if 'tokens' in data:
        club.tokens = int(data['tokens'])

    if 'balance' in data:
        club.balance = int(data['balance'])

    club.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    # Sync changes to Airtable (only name, description, location)
    airtable_synced = False
    if changes:
        airtable_data = club.get_airtable_data()
        airtable_id = airtable_data.get('airtable_id') if airtable_data else None

        if airtable_id:
            try:
                airtable_service = AirtableService()
                airtable_synced = airtable_service.update_club_info(
                    airtable_id,
                    changes,
                    club_name=old_name  # Use old name for fallback search
                )
                if not airtable_synced:
                    current_app.logger.warning(f"Failed to sync club info to Airtable for club {club_id}")
            except Exception as e:
                current_app.logger.error(f"Error syncing club info to Airtable: {str(e)}")

    create_audit_log(
        action_type='club_update',
        description=f'Admin {current_user.username} updated club {club.name}',
        user=current_user,
        target_type='club',
        target_id=club_id,
        details={'updated_fields': list(data.keys()), 'airtable_synced': airtable_synced},
        severity='info',
        admin_action=True,
        category='admin'
    )

    sync_message = ' and synced to Airtable' if airtable_synced and changes else ''
    
    return jsonify({
        'success': True,
        'message': f'Club updated successfully{sync_message}',
        'club': {
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'location': club.location,
            'tokens': club.tokens,
            'balance': club.balance
        }
    })


@api_bp.route('/admin/clubs/<int:club_id>', methods=['DELETE'])
@login_required
@permission_required('clubs.delete')
def admin_delete_club(club_id):
    """Delete a club (requires clubs.delete permission)"""
    from app.services.airtable import AirtableService
    
    club = Club.query.get_or_404(club_id)
    current_user = get_current_user()

    club_name = club.name
    
    try:
        # Try to unmark club as onboarded in Airtable if it has an Airtable ID
        airtable_data = club.get_airtable_data()
        airtable_id = airtable_data.get('airtable_id') if airtable_data else None
        
        if airtable_id:
            try:
                airtable_service = AirtableService()
                airtable_service.unmark_club_onboarded(airtable_id, club_name=club.name)
            except Exception as e:
                current_app.logger.warning(f"Failed to update Airtable when deleting club {club_name}: {str(e)}")
                # Continue with deletion even if Airtable update fails

        db.session.delete(club)
        db.session.commit()

        create_audit_log(
            action_type='club_delete',
            description=f'Admin {current_user.username} deleted club {club_name}',
            user=current_user,
            target_type='club',
            target_id=club_id,
            details={'club_name': club_name, 'airtable_updated': airtable_id is not None},
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Club deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting club {club_name}: {str(e)}")
        return jsonify({
            'error': 'Failed to delete club',
            'details': str(e)
        }), 500


@api_bp.route('/api/admin/clubs/<int:club_id>/sync-from-airtable', methods=['POST'])
@login_required
@permission_required('clubs.edit')
def admin_sync_club_from_airtable(club_id):
    """Manually sync a club from Airtable to refresh data including team notes"""
    from app.services.airtable import AirtableService
    
    club = Club.query.get_or_404(club_id)
    current_user = get_current_user()
    
    try:
        airtable_service = AirtableService()
        
        # Get the club's Airtable data
        airtable_data = club.get_airtable_data()
        airtable_id = airtable_data.get('airtable_id') if airtable_data else None
        
        if not airtable_id:
            return jsonify({'error': 'Club does not have an Airtable ID'}), 400
        
        # Fetch fresh club data using leader email (gets full data)
        if club.leader:
            clubs = airtable_service.get_clubs_by_leader_email(club.leader.email)
            matching_club = None
            for c in clubs:
                if c.get('airtable_id') == airtable_id:
                    matching_club = c.get('airtable_data', c)  # Use nested airtable_data if available
                    break
            
            if matching_club:
                # Sync the club
                success = airtable_service.sync_club_with_airtable(club.id, matching_club)
                
                if success:
                    create_audit_log(
                        action_type='club_synced_from_airtable',
                        description=f'Manually synced club {club.name} from Airtable',
                        user=current_user,
                        target_type='club',
                        target_id=club_id,
                        category='club'
                    )
                    
                    return jsonify({
                        'success': True,
                        'message': f'Successfully synced {club.name} from Airtable'
                    })
                else:
                    return jsonify({'error': 'Failed to sync club from Airtable'}), 500
            else:
                return jsonify({'error': 'Club not found in Airtable'}), 404
        else:
            return jsonify({'error': 'Club does not have a leader'}), 400
            
    except Exception as e:
        current_app.logger.error(f"Error syncing club {club.name} from Airtable: {str(e)}")
        return jsonify({
            'error': 'Failed to sync club',
            'details': str(e)
        }), 500


@api_bp.route('/admin/clubs/<int:club_id>/sync-immune', methods=['POST'])
@login_required
@permission_required('clubs.edit')
def admin_sync_club_immune(club_id):
    """Set club sync immunity status (requires clubs.edit permission)"""
    club = Club.query.get_or_404(club_id)
    current_user = get_current_user()

    data = request.get_json()
    immune = data.get('sync_immune', data.get('immune', False))

    if not hasattr(club, 'sync_immune'):
        return jsonify({'error': 'Sync immune feature not yet implemented'}), 501

    club.sync_immune = immune
    db.session.commit()

    create_audit_log(
        action_type='club_sync_immune',
        description=f'Admin {current_user.username} set sync immune to {immune} for club {club.name}',
        user=current_user,
        target_type='club',
        target_id=club_id,
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': f'Club sync immunity {"enabled" if immune else "disabled"}'
    })


@api_bp.route('/admin/clubs/<int:club_id>/transfer-leadership', methods=['POST'])
@login_required
@permission_required('clubs.edit')
def admin_transfer_club_leadership(club_id):
    """Transfer club leadership to another user (requires clubs.edit permission)"""
    club = Club.query.get_or_404(club_id)
    current_user = get_current_user()

    data = request.get_json()
    new_leader_id = data.get('new_leader_id')

    if not new_leader_id:
        return jsonify({'error': 'new_leader_id is required'}), 400

    new_leader = User.query.get_or_404(new_leader_id)

    old_leader_id = club.leader_id
    club.leader_id = new_leader_id
    db.session.commit()

    create_audit_log(
        action_type='club_leadership_transfer',
        description=f'Admin {current_user.username} transferred leadership of {club.name} to {new_leader.username}',
        user=current_user,
        target_type='club',
        target_id=club_id,
        details={'old_leader_id': old_leader_id, 'new_leader_id': new_leader_id},
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': f'Leadership transferred to {new_leader.username}'
    })
@api_bp.route('/admin/pizza-grants', methods=['GET'])
@login_required
@admin_required
def admin_get_pizza_grants():
    """Get all pizza grants from Airtable (admin only)"""
    try:
        grants = airtable_service.get_pizza_grants()
        return jsonify({'grants': grants})
    except Exception as e:
        current_app.logger.error(f'Error fetching pizza grants: {str(e)}')
        return jsonify({'error': 'Failed to fetch pizza grants', 'grants': []}), 500


@api_bp.route('/admin/pizza-grants/review', methods=['POST'])
@login_required
@admin_required
def admin_review_pizza_grant():
    """Review a pizza grant (admin only)"""
    current_user = get_current_user()
    data = request.get_json()

    grant_id = data.get('grant_id')
    status = data.get('status')  # 'approved' or 'rejected'
    notes = sanitize_string(data.get('notes', ''), max_length=1000)

    if not grant_id or not status:
        return jsonify({'error': 'grant_id and status are required'}), 400

    try:
        success = airtable_service.update_pizza_grant(grant_id, status, notes, current_user.username)

        if success:
            create_audit_log(
                action_type='pizza_grant_review',
                description=f'Admin {current_user.username} {status} pizza grant {grant_id}',
                user=current_user,
                target_type='pizza_grant',
                target_id=grant_id,
                details={'status': status, 'notes': notes},
                severity='info',
                admin_action=True,
                category='admin'
            )

            return jsonify({'success': True, 'message': f'Grant {status}'})
        else:
            return jsonify({'error': 'Failed to update grant'}), 500
    except Exception as e:
        current_app.logger.error(f'Error reviewing pizza grant: {str(e)}')
        return jsonify({'error': 'Failed to review grant'}), 500


@api_bp.route('/admin/pizza-grants/<string:grant_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_pizza_grant(grant_id):
    """Delete a pizza grant (admin only)"""
    current_user = get_current_user()

    try:
        success = airtable_service.delete_pizza_grant(grant_id)

        if success:
            create_audit_log(
                action_type='pizza_grant_delete',
                description=f'Admin {current_user.username} deleted pizza grant {grant_id}',
                user=current_user,
                target_type='pizza_grant',
                target_id=grant_id,
                severity='warning',
                admin_action=True,
                category='admin'
            )

            return jsonify({'success': True, 'message': 'Grant deleted'})
        else:
            return jsonify({'error': 'Failed to delete grant'}), 500
    except Exception as e:
        current_app.logger.error(f'Error deleting pizza grant: {str(e)}')
        return jsonify({'error': 'Failed to delete grant'}), 500
@api_bp.route('/admin/rbac/users/<int:user_id>/roles', methods=['POST'])
@login_required
@permission_required('users.assign_roles', 'system.manage_roles')
def admin_assign_role_to_user(user_id):
    """Assign a role to a user (admin only)"""
    from app.models.user import Role

    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    data = request.get_json()
    role_name = data.get('role_name')

    if not role_name:
        return jsonify({'error': 'role_name is required'}), 400

    role = Role.query.filter_by(name=role_name).first()
    if not role:
        return jsonify({'error': 'Role not found'}), 404

    if user.has_role(role_name):
        return jsonify({'error': 'User already has this role'}), 400

    user.assign_role(role, current_user)
    db.session.commit()

    create_audit_log(
        action_type='role_assign',
        description=f'Admin {current_user.username} assigned role "{role_name}" to {user.username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        details={'role': role_name},
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': f'Role "{role_name}" assigned to user'
    })


@api_bp.route('/admin/rbac/users/<int:user_id>/roles/<string:role_name>', methods=['DELETE'])
@login_required
@permission_required('users.assign_roles')
def admin_remove_role_from_user(user_id, role_name):
    """Remove a role from a user (admin only)"""
    user = User.query.get_or_404(user_id)
    current_user = get_current_user()

    if user.is_root_user() and role_name == 'super-admin':
        return jsonify({'error': 'Cannot remove super-admin from root user'}), 403

    if not user.has_role(role_name):
        return jsonify({'error': 'User does not have this role'}), 400

    user.remove_role(role_name)
    db.session.commit()

    create_audit_log(
        action_type='role_remove',
        description=f'Admin {current_user.username} removed role "{role_name}" from {user.username}',
        user=current_user,
        target_type='user',
        target_id=user_id,
        details={'role': role_name},
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': f'Role "{role_name}" removed from user'
    })


@api_bp.route('/admin/rbac/initialize', methods=['POST'])
@login_required
@admin_required
def admin_initialize_rbac():
    """Initialize the RBAC system (admin only)"""
    from app.models.user import initialize_rbac_system

    current_user = get_current_user()

    try:
        initialize_rbac_system()

        create_audit_log(
            action_type='rbac_initialize',
            description=f'Admin {current_user.username} initialized RBAC system',
            user=current_user,
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'RBAC system initialized successfully'
        })
    except Exception as e:
        current_app.logger.error(f'Error initializing RBAC: {str(e)}')
        return jsonify({'error': 'Failed to initialize RBAC system'}), 500


@api_bp.route('/admin/rbac/roles', methods=['POST'])
@login_required
@permission_required('system.manage_roles')
def admin_create_role():
    """Create a new role (admin only)"""
    from app.models.user import Role, Permission

    current_user = get_current_user()
    data = request.get_json()

    name = sanitize_string(data.get('name', ''), max_length=50)
    display_name = sanitize_string(data.get('display_name', ''), max_length=100)
    description = sanitize_string(data.get('description', ''), max_length=500)
    requires_2fa = data.get('requires_2fa', False)
    permission_names = data.get('permissions', [])

    if not name or not display_name:
        return jsonify({'error': 'name and display_name are required'}), 400

    existing_role = Role.query.filter_by(name=name).first()
    if existing_role:
        return jsonify({'error': 'Role already exists'}), 400

    role = Role(
        name=name,
        display_name=display_name,
        description=description,
        is_system_role=False,
        requires_2fa=requires_2fa
    )
    db.session.add(role)
    db.session.flush()

    for perm_name in permission_names:
        permission = Permission.query.filter_by(name=perm_name).first()
        if permission:
            from app.models.user import RolePermission
            role_perm = RolePermission(role_id=role.id, permission_id=permission.id)
            db.session.add(role_perm)

    db.session.commit()

    create_audit_log(
        action_type='role_create',
        description=f'Admin {current_user.username} created role "{name}"' + (' (requires 2FA)' if requires_2fa else ''),
        user=current_user,
        target_type='role',
        target_id=role.id,
        details={'name': name, 'permissions': permission_names, 'requires_2fa': requires_2fa},
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'Role created successfully',
        'role': role.to_dict()
    })


@api_bp.route('/admin/rbac/roles/<int:role_id>', methods=['PUT'])
@login_required
@permission_required('system.manage_roles')
def admin_update_role(role_id):
    """Update a role (admin only)"""
    from app.models.user import Role, Permission, RolePermission

    role = Role.query.get_or_404(role_id)
    current_user = get_current_user()

    data = request.get_json()

    if 'display_name' in data:
        role.display_name = sanitize_string(data['display_name'], max_length=100)

    if 'description' in data:
        role.description = sanitize_string(data['description'], max_length=500)

    if 'requires_2fa' in data:
        role.requires_2fa = data['requires_2fa']

    if 'permissions' in data:
        RolePermission.query.filter_by(role_id=role.id).delete()

        for perm_name in data['permissions']:
            permission = Permission.query.filter_by(name=perm_name).first()
            if permission:
                role_perm = RolePermission(role_id=role.id, permission_id=permission.id)
                db.session.add(role_perm)

    db.session.commit()

    create_audit_log(
        action_type='role_update',
        description=f'Admin {current_user.username} updated role "{role.name}"' + (' (requires 2FA)' if role.requires_2fa else ''),
        user=current_user,
        target_type='role',
        target_id=role_id,
        details={'requires_2fa': role.requires_2fa},
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'Role updated successfully',
        'role': role.to_dict()
    })


@api_bp.route('/admin/rbac/roles/<int:role_id>/users', methods=['GET'])
@login_required
@admin_required
def admin_get_role_users(role_id):
    """Get all users assigned to a specific role"""
    from app.models.user import Role, User

    role = Role.query.get_or_404(role_id)

    users = User.query.join(User.roles).filter(Role.id == role_id).all()

    def get_user_avatar(user):
        return '/static/assets/heidi-avatar.png'

    return jsonify({
        'success': True,
        'role': {
            'id': role.id,
            'name': role.name,
            'display_name': role.display_name
        },
        'users': [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'avatar_url': get_user_avatar(user)
        } for user in users]
    })


@api_bp.route('/admin/rbac/roles/<int:role_id>', methods=['DELETE'])
@login_required
@permission_required('system.manage_roles')
def admin_delete_role(role_id):
    """Delete a role (admin only)"""
    from app.models.user import Role, UserRole

    role = Role.query.get_or_404(role_id)
    current_user = get_current_user()

    users_with_role = UserRole.query.filter_by(role_id=role_id).count()
    force = request.args.get('force') == 'true'

    if users_with_role > 0 and not force:
        return jsonify({
            'error': f'Role is assigned to {users_with_role} users. Use force=true to delete anyway.',
            'users_count': users_with_role
        }), 400

    role_name = role.name

    db.session.delete(role)
    db.session.commit()

    create_audit_log(
        action_type='role_delete',
        description=f'Admin {current_user.username} deleted role "{role_name}"',
        user=current_user,
        target_type='role',
        target_id=role_id,
        details={'role_name': role_name, 'force': force},
        severity='warning',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'Role deleted successfully'
    })
@api_bp.route('/admin/banner-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_banner_settings():
    """Get or update banner settings (admin only)"""
    if request.method == 'GET':
        banner_enabled = SystemSettings.get_setting('banner_enabled', 'false') == 'true'
        banner_message = SystemSettings.get_setting('banner_message', '')
        banner_type = SystemSettings.get_setting('banner_type', 'info')  # info, warning, error

        return jsonify({
            'enabled': banner_enabled,
            'message': banner_message,
            'type': banner_type
        })

    elif request.method == 'POST':
        current_user = get_current_user()
        data = request.get_json()

        if 'enabled' in data:
            SystemSettings.set_setting('banner_enabled', str(data['enabled']).lower(), current_user.id)

        if 'message' in data:
            message = sanitize_string(data['message'], max_length=500)
            SystemSettings.set_setting('banner_message', message, current_user.id)

        if 'type' in data:
            banner_type = data['type']
            if banner_type in ['info', 'warning', 'error']:
                SystemSettings.set_setting('banner_type', banner_type, current_user.id)

        create_audit_log(
            action_type='banner_settings_update',
            description=f'Admin {current_user.username} updated banner settings',
            user=current_user,
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Banner settings updated'
        })
@api_bp.route('/admin/orders', methods=['GET'])
@login_required
@admin_required
@limiter.limit("100 per minute")
def admin_get_orders():
    """Get all orders from Airtable (admin only)"""
    from app.services.airtable import AirtableService

    airtable_service = AirtableService()

    try:
        all_orders = airtable_service.get_all_orders()

        status_filter = request.args.get('status')
        search = request.args.get('search')

        filtered_orders = all_orders

        if status_filter:
            filtered_orders = [o for o in filtered_orders if o.get('shipment_status', '').lower() == status_filter.lower()]

        if search:
            search_lower = search.lower()
            filtered_orders = [
                o for o in filtered_orders
                if search_lower in o.get('club_name', '').lower() or
                   search_lower in o.get('leader_email', '').lower() or
                   search_lower in o.get('leader_first_name', '').lower() or
                   search_lower in o.get('leader_last_name', '').lower()
            ]

        return jsonify({
            'orders': filtered_orders,
            'total': len(filtered_orders)
        })
    except Exception as e:
        return jsonify({'error': str(e), 'orders': []}), 500


@api_bp.route('/admin/orders/<string:order_id>/status', methods=['PATCH'])
@login_required
@permission_required('orders.approve')
def admin_update_order_status(order_id):
    """Update order status in Airtable (admin only)"""
    from app.services.airtable import AirtableService

    airtable_service = AirtableService()
    current_user = get_current_user()

    data = request.get_json()
    new_status = data.get('status')
    reviewer_reason = data.get('reviewer_reason', '')

    if not new_status:
        return jsonify({'error': 'status is required'}), 400

    valid_statuses = ['Pending', 'Approved', 'Rejected', 'Shipped', 'Delivered']
    if new_status not in valid_statuses:
        return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400

    success = airtable_service.update_order_status(order_id, new_status, reviewer_reason)

    if success:
        create_audit_log(
            action_type='order_status_update',
            description=f'Admin {current_user.username} changed order {order_id} status to {new_status}',
            user=current_user,
            target_type='order',
            target_id=order_id,
            details={'new_status': new_status},
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Order status updated'
        })
    else:
        return jsonify({'error': 'Failed to update order status'}), 500


@api_bp.route('/admin/orders/<string:order_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_order(order_id):
    """Delete an order from Airtable (admin only)"""
    from app.services.airtable import AirtableService

    airtable_service = AirtableService()
    current_user = get_current_user()

    success = airtable_service.delete_order(order_id)

    if success:
        create_audit_log(
            action_type='order_delete',
            description=f'Admin {current_user.username} deleted order {order_id}',
            user=current_user,
            target_type='order',
            target_id=order_id,
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Order deleted'
        })
    else:
        return jsonify({'error': 'Failed to delete order'}), 500

    order = Order.query.get_or_404(order_id)
    current_user = get_current_user()

    order_info = f'Order #{order.id} from {order.club.name if order.club else "Unknown"}'

    db.session.delete(order)
    db.session.commit()

    create_audit_log(
        action_type='order_delete',
        description=f'Admin {current_user.username} deleted {order_info}',
        user=current_user,
        target_type='order',
        target_id=order_id,
        severity='warning',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'Order deleted successfully'
    })


@api_bp.route('/admin/orders/<string:order_id>/refund', methods=['POST'])
@login_required
@admin_required
def admin_refund_order(order_id):
    """Reject/refund an order in Airtable (admin only)"""
    from app.services.airtable import AirtableService

    airtable_service = AirtableService()
    current_user = get_current_user()

    data = request.get_json() or {}
    reason = data.get('reason', 'Order refunded/rejected by admin')

    success = airtable_service.update_order_status(order_id, 'Rejected', reason)

    if success:
        create_audit_log(
            action_type='order_refund',
            description=f'Admin {current_user.username} refunded/rejected order {order_id}',
            user=current_user,
            target_type='order',
            target_id=order_id,
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Order refunded/rejected successfully'
        })
    else:
        return jsonify({'error': 'Failed to refund order'}), 500
@api_bp.route('/admin/shop-items', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_shop_items():
    """Get or create shop items (admin only)"""
    from app.models.shop import ShopItem

    if request.method == 'GET':
        items = ShopItem.query.order_by(ShopItem.created_at.desc()).all()

        items_by_category = {}
        for item in items:
            category = item.category or 'Other'
            if category not in items_by_category:
                items_by_category[category] = []
            items_by_category[category].append(item.to_dict())

        return jsonify({
            'items': items_by_category,
            'all_items': [item.to_dict() for item in items]
        })

    elif request.method == 'POST':
        current_user = get_current_user()
        data = request.get_json()

        name = sanitize_string(data.get('name', ''), max_length=200)
        description = sanitize_string(data.get('description', ''), max_length=2000)
        price = int(data.get('price', 0))
        image_url = sanitize_string(data.get('image_url', ''), max_length=500)
        category = sanitize_string(data.get('category', ''), max_length=100)
        stock = int(data.get('stock', 0))
        is_active = bool(data.get('is_active', True))

        if not name or price < 0:
            return jsonify({'error': 'Name is required and price must be positive'}), 400

        shop_item = ShopItem(
            name=name,
            description=description,
            price=price,
            image_url=image_url,
            category=category,
            stock=stock,
            is_active=is_active
        )
        db.session.add(shop_item)
        db.session.commit()

        create_audit_log(
            action_type='shop_item_create',
            description=f'Admin {current_user.username} created shop item "{name}"',
            user=current_user,
            target_type='shop_item',
            target_id=shop_item.id,
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Shop item created',
            'item': shop_item.to_dict()
        })


@api_bp.route('/admin/shop-items/<int:item_id>', methods=['PUT', 'DELETE'])
@login_required
@admin_required
def admin_shop_item(item_id):
    """Update or delete a shop item (admin only)"""
    from app.models.shop import ShopItem

    shop_item = ShopItem.query.get_or_404(item_id)
    current_user = get_current_user()

    if request.method == 'PUT':
        data = request.get_json()

        if 'name' in data:
            shop_item.name = sanitize_string(data['name'], max_length=200)
        if 'description' in data:
            shop_item.description = sanitize_string(data['description'], max_length=2000)
        if 'price' in data:
            shop_item.price = int(data['price'])
        if 'image_url' in data:
            shop_item.image_url = sanitize_string(data['image_url'], max_length=500)
        if 'category' in data:
            shop_item.category = sanitize_string(data['category'], max_length=100)
        if 'stock' in data:
            shop_item.stock = int(data['stock'])
        if 'is_active' in data:
            shop_item.is_active = bool(data['is_active'])

        db.session.commit()

        create_audit_log(
            action_type='shop_item_update',
            description=f'Admin {current_user.username} updated shop item "{shop_item.name}"',
            user=current_user,
            target_type='shop_item',
            target_id=shop_item.id,
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Shop item updated',
            'item': shop_item.to_dict()
        })

    elif request.method == 'DELETE':
        item_name = shop_item.name

        db.session.delete(shop_item)
        db.session.commit()

        create_audit_log(
            action_type='shop_item_delete',
            description=f'Admin {current_user.username} deleted shop item "{item_name}"',
            user=current_user,
            target_type='shop_item',
            target_id=item_id,
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Shop item deleted'
        })
@api_bp.route('/admin/leaderboard/exclusions', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_leaderboard_exclusions():
    """Get or manage leaderboard exclusions (admin only)"""
    from app.models.economy import LeaderboardExclusion

    if request.method == 'GET':
        exclusions = LeaderboardExclusion.query.all()
        exclusions_data = []
        for exclusion in exclusions:
            club = Club.query.get(exclusion.club_id) if exclusion.club_id else None
            exclusions_data.append({
                'id': exclusion.id,
                'club_id': exclusion.club_id,
                'club_name': club.name if club else 'Unknown',
                'reason': exclusion.reason,
                'created_at': exclusion.created_at.isoformat() if exclusion.created_at else None
            })

        return jsonify({'exclusions': exclusions_data})

    elif request.method == 'POST':
        current_user = get_current_user()
        data = request.get_json()

        club_id = data.get('club_id')
        reason = sanitize_string(data.get('reason', ''), max_length=500)

        if not club_id:
            return jsonify({'error': 'club_id is required'}), 400

        club = Club.query.get(club_id)
        if not club:
            return jsonify({'error': 'Club not found'}), 404

        existing = LeaderboardExclusion.query.filter_by(club_id=club_id).first()
        if existing:
            return jsonify({'error': 'Club already excluded from leaderboard'}), 400

        exclusion = LeaderboardExclusion(club_id=club_id, reason=reason)
        db.session.add(exclusion)
        db.session.commit()

        create_audit_log(
            action_type='leaderboard_exclusion_add',
            description=f'Admin {current_user.username} excluded club {club.name} from leaderboard',
            user=current_user,
            target_type='club',
            target_id=club_id,
            details={'reason': reason},
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Club excluded from leaderboard'
        })


@api_bp.route('/admin/leaderboard/exclusions/<int:exclusion_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_leaderboard_exclusion(exclusion_id):
    """Remove a leaderboard exclusion (admin only)"""
    from app.models.economy import LeaderboardExclusion

    current_user = get_current_user()
    exclusion = LeaderboardExclusion.query.get_or_404(exclusion_id)

    club = Club.query.get(exclusion.club_id) if exclusion.club_id else None
    club_name = club.name if club else 'Unknown'

    db.session.delete(exclusion)
    db.session.commit()

    create_audit_log(
        action_type='leaderboard_exclusion_remove',
        description=f'Admin {current_user.username} removed leaderboard exclusion for club {club_name}',
        user=current_user,
        target_type='club',
        target_id=exclusion.club_id,
        severity='info',
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'success': True,
        'message': 'Leaderboard exclusion removed'
    })
@api_bp.route('/user/me', methods=['GET'])
@login_required
def get_user_me():
    """Get current authenticated user information"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_admin': user.is_admin,
        'is_suspended': user.is_suspended,
        'created_at': user.created_at.isoformat() if user.created_at else None
    })


@api_bp.route('/user/update', methods=['POST', 'PUT'])
@login_required
@limiter.limit("20 per hour")
def update_user():
    """Update current user's profile"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()

    if 'first_name' in data:
        user.first_name = sanitize_string(data['first_name'], max_length=50)

    if 'last_name' in data:
        user.last_name = sanitize_string(data['last_name'], max_length=50)

    if 'username' in data:
        new_username = sanitize_string(data['username'], max_length=30).strip()
        if new_username != user.username:
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                return jsonify({'error': 'Username already taken'}), 400
        user.username = new_username

    if 'email' in data:
        new_email = sanitize_string(data['email'], max_length=120).strip().lower()
        if new_email != user.email:
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user:
                return jsonify({'error': 'Email already taken'}), 400
        user.email = new_email

    if 'birthday' in data:
        user.birthday = data['birthday'] if data['birthday'] else None

    if 'hackatime_api_key' in data:
        user.hackatime_api_key = sanitize_string(data['hackatime_api_key'], max_length=500)

    if 'avatar_url' in data:
        user.avatar_url = sanitize_string(data['avatar_url'], max_length=500)

    if 'current_password' in data and 'new_password' in data:
        current_password = data['current_password']
        new_password = data['new_password']

        if not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400

        is_valid, validation_message = validate_password(new_password)
        if not is_valid:
            return jsonify({'error': validation_message}), 400

        user.set_password(new_password)

    db.session.commit()

    create_audit_log(
        action_type='user_profile_update',
        description=f'User {user.username} updated their profile',
        user=user,
        target_type='user',
        target_id=user.id,
        category='user'
    )

    return jsonify({
        'success': True,
        'message': 'Profile updated successfully'
    })
@api_bp.route('/identity/status', methods=['GET'])
@login_required
def identity_status():
    """Get Hack Club identity status for current user"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    has_identity = bool(user.identity_token and user.identity_verified)
    slack_id = user.slack_user_id if user.slack_user_id else None

    return jsonify({
        'linked': has_identity,
        'verified': user.identity_verified,
        'slack_id': slack_id,
        'status': 'verified' if has_identity else 'unverified'
    })


@api_bp.route('/identity/authorize', methods=['GET', 'POST'])
@login_required
def identity_authorize():
    """Start Hack Club identity authorization flow"""
    import os
    import secrets
    from app.services.identity import HackClubIdentityService, init_service

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    client_id = os.getenv('HACKCLUB_IDENTITY_CLIENT_ID')
    client_secret = os.getenv('HACKCLUB_IDENTITY_CLIENT_SECRET')
    identity_url = os.getenv('HACKCLUB_IDENTITY_URL', 'https://identity.hackclub.com')

    if not client_id or not client_secret:
        return jsonify({
            'error': 'Identity provider not configured',
            'message': 'Hack Club Identity OAuth is not configured on this server'
        }), 503

    init_service(current_app._get_current_object(), identity_url, client_id, client_secret)
    identity_service = HackClubIdentityService()

    state = secrets.token_urlsafe(32)
    session['hackclub_identity_state'] = state

    redirect_uri = request.url_root.rstrip('/') + '/auth/identity/callback'
    if request.url_root.startswith('http://'):
        redirect_uri = redirect_uri.replace('http://', 'https://', 1)

    auth_url = identity_service.get_auth_url(redirect_uri, state)

    return jsonify({
        'url': auth_url,
        'state': state
    })
@api_bp.route('/status/banner', methods=['GET'])
def status_banner():
    """Get public banner settings"""
    banner_enabled = SystemSettings.get_setting('banner_enabled', 'false') == 'true'
    banner_message = SystemSettings.get_setting('banner_message', '')
    banner_type = SystemSettings.get_setting('banner_type', 'info')

    return jsonify({
        'enabled': banner_enabled,
        'message': banner_message,
        'type': banner_type
    })


@api_bp.route('/status/summary', methods=['GET'])
def status_summary():
    """Get system status summary"""
    total_users = User.query.count()
    total_clubs = Club.query.count()

    maintenance_mode = SystemSettings.is_maintenance_mode()

    return jsonify({
        'status': 'operational' if not maintenance_mode else 'maintenance',
        'maintenance_mode': maintenance_mode,
        'stats': {
            'total_users': total_users,
            'total_clubs': total_clubs
        }
    })


@api_bp.route('/admin/status/incidents', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_status_incidents():
    """Manage status incidents (admin only)"""
    from app.models.system import StatusIncident, StatusUpdate
    from datetime import datetime

    if request.method == 'GET':
        status_filter = request.args.get('status')  # investigating, identified, monitoring, resolved
        limit = request.args.get('limit', 50, type=int)
        limit = min(limit, 100)

        query = StatusIncident.query

        if status_filter:
            query = query.filter(StatusIncident.status == status_filter)

        incidents = query.order_by(StatusIncident.created_at.desc()).limit(limit).all()
        incidents_data = [incident.to_dict() for incident in incidents]

        return jsonify({
            'incidents': incidents_data,
            'total': len(incidents_data)
        })

    elif request.method == 'POST':
        current_user = get_current_user()
        data = request.get_json()

        title = sanitize_string(data.get('title', ''), max_length=255)
        description = sanitize_string(data.get('description', ''), max_length=5000)
        status = data.get('status', 'investigating')
        impact = data.get('impact', 'minor')
        affected_services = data.get('affected_services', [])

        if not title or not description:
            return jsonify({'error': 'Title and description are required'}), 400

        valid_statuses = ['investigating', 'identified', 'monitoring', 'resolved']
        if status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400

        valid_impacts = ['minor', 'major', 'critical']
        if impact not in valid_impacts:
            return jsonify({'error': f'Invalid impact. Must be one of: {", ".join(valid_impacts)}'}), 400

        incident = StatusIncident(
            title=title,
            description=description,
            status=status,
            impact=impact,
            created_by=current_user.id
        )
        incident.set_affected_services(affected_services)

        db.session.add(incident)
        db.session.commit()

        create_audit_log(
            action_type='status_incident_create',
            description=f'Admin {current_user.username} created status incident "{title}"',
            user=current_user,
            target_type='status_incident',
            target_id=incident.id,
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Status incident created',
            'incident': incident.to_dict()
        })


@api_bp.route('/admin/status/incidents/<int:incident_id>', methods=['PUT', 'DELETE'])
@login_required
@admin_required
def admin_status_incident(incident_id):
    """Update or delete a status incident (admin only)"""
    from app.models.system import StatusIncident
    from datetime import datetime

    incident = StatusIncident.query.get_or_404(incident_id)
    current_user = get_current_user()

    if request.method == 'PUT':
        data = request.get_json()

        if 'title' in data:
            incident.title = sanitize_string(data['title'], max_length=255)
        if 'description' in data:
            incident.description = sanitize_string(data['description'], max_length=5000)
        if 'status' in data:
            new_status = data['status']
            valid_statuses = ['investigating', 'identified', 'monitoring', 'resolved']
            if new_status not in valid_statuses:
                return jsonify({'error': f'Invalid status'}), 400
            incident.status = new_status

            if new_status == 'resolved' and not incident.resolved_at:
                incident.resolved_at = datetime.utcnow()

        if 'impact' in data:
            impact = data['impact']
            valid_impacts = ['minor', 'major', 'critical']
            if impact not in valid_impacts:
                return jsonify({'error': f'Invalid impact'}), 400
            incident.impact = impact

        if 'affected_services' in data:
            incident.set_affected_services(data['affected_services'])

        db.session.commit()

        create_audit_log(
            action_type='status_incident_update',
            description=f'Admin {current_user.username} updated status incident "{incident.title}"',
            user=current_user,
            target_type='status_incident',
            target_id=incident.id,
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Status incident updated',
            'incident': incident.to_dict()
        })

    elif request.method == 'DELETE':
        incident_title = incident.title

        db.session.delete(incident)
        db.session.commit()

        create_audit_log(
            action_type='status_incident_delete',
            description=f'Admin {current_user.username} deleted status incident "{incident_title}"',
            user=current_user,
            target_type='status_incident',
            target_id=incident_id,
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Status incident deleted'
        })


@api_bp.route('/admin/status/incidents/<int:incident_id>/updates', methods=['POST'])
@login_required
@admin_required
def admin_create_status_update(incident_id):
    """Add an update to a status incident (admin only)"""
    from app.models.system import StatusIncident, StatusUpdate

    incident = StatusIncident.query.get_or_404(incident_id)
    current_user = get_current_user()

    data = request.get_json()
    message = sanitize_string(data.get('message', ''), max_length=5000)
    status = data.get('status', incident.status)

    if not message:
        return jsonify({'error': 'Message is required'}), 400

    valid_statuses = ['investigating', 'identified', 'monitoring', 'resolved']
    if status not in valid_statuses:
        return jsonify({'error': 'Invalid status'}), 400

    update = StatusUpdate(
        incident_id=incident.id,
        message=message,
        status=status,
        created_by=current_user.id
    )
    db.session.add(update)

    incident.status = status
    if status == 'resolved' and not incident.resolved_at:
        incident.resolved_at = datetime.utcnow()

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Status update added',
        'update': update.to_dict()
    })
@api_bp.route('/user/projects/pending', methods=['GET'])
@login_required
def get_projects_for_review():
    """Get projects pending review from Airtable"""
    from app.services.airtable import AirtableService

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    airtable_service = AirtableService()
    all_projects = airtable_service.get_ysws_project_submissions()

    user_projects = [
        p for p in all_projects
        if p.get('email', '').lower() == user.email.lower() and
        p.get('status', '').lower() in ['pending', '']
    ]

    user_projects.sort(key=lambda x: x.get('createdTime', ''), reverse=True)

    projects_data = []
    for project in user_projects:
        projects_data.append({
            'id': project.get('id'),
            'name': f"{project.get('firstName', '')} {project.get('lastName', '')}".strip(),
            'description': project.get('description', ''),
            'url': project.get('playableUrl', ''),
            'github_url': project.get('codeUrl', ''),
            'created_at': project.get('createdTime', ''),
            'status': project.get('status', 'pending').lower()
        })

    return jsonify({
        'projects': projects_data,
        'total': len(projects_data)
    })


@api_bp.route('/projects/review', methods=['GET'])
@login_required
@reviewer_required
@limiter.limit("100 per hour")
def api_get_project_submissions():
    """Get all YSWS project submissions for review"""
    from app.services.airtable import AirtableService

    try:
        airtable_service = AirtableService()
        submissions = airtable_service.get_ysws_project_submissions()

        return jsonify({
            'success': True,
            'projects': submissions
        })
    except Exception as e:
        logger.error(f"Error fetching project submissions: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch project submissions'
        }), 500


@api_bp.route('/projects/review/<string:project_id>', methods=['PUT'])
@login_required
@reviewer_required
@limiter.limit("50 per hour")
def api_update_project_review(project_id):
    """Update the review status of a YSWS project submission"""
    from app.services.airtable import AirtableService

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        new_status = data.get('status')
        decision_reason = data.get('decisionReason')

        if not new_status or not decision_reason:
            return jsonify({'error': 'Status and decision reason are required'}), 400

        valid_statuses = ['Pending', 'Approved', 'Rejected', 'Flagged']
        if new_status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400

        airtable_service = AirtableService()
        current_user = get_current_user()

        update_fields = {
            'Status': new_status,
            'Decision Reason': decision_reason
        }

        success = airtable_service.update_ysws_project_submission(project_id, update_fields)

        if not success:
            return jsonify({'error': 'Failed to update project status in Airtable'}), 500

        create_audit_log(
            action_type='project_review',
            description=f"{('Admin' if current_user.is_admin else 'Reviewer')} {current_user.username} reviewed project submission: {new_status}",
            user=current_user,
            target_type='project',
            target_id=project_id,
            details={'status': new_status, 'reason': decision_reason},
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': f'Project {new_status.lower()} successfully'
        })

    except Exception as e:
        logger.error(f"Error updating project review: {str(e)}")
        return jsonify({'error': 'Failed to update project review'}), 500


@api_bp.route('/projects/review/<string:project_id>', methods=['POST'])
@login_required
@admin_required
def review_project(project_id):
    """Review and approve/reject a project in Airtable (admin only)"""
    from app.services.airtable import AirtableService
    from datetime import datetime

    airtable_service = AirtableService()
    current_user = get_current_user()

    data = request.get_json()
    approved = data.get('approved', False)
    admin_notes = sanitize_string(data.get('admin_notes', ''), max_length=2000)

    if approved:
        success = airtable_service.update_ysws_project_submission(project_id, {
            'Status': 'Approved',
            'Decision Reason': admin_notes or f'Approved by {current_user.username}'
        })

        if success:
            create_audit_log(
                action_type='project_approval',
                description=f'Admin {current_user.username} approved project {project_id}',
                user=current_user,
                target_type='project',
                target_id=project_id,
                severity='info',
                admin_action=True,
                category='admin'
            )
            message = 'Project approved'
        else:
            return jsonify({'error': 'Failed to approve project'}), 500
    else:
        success = airtable_service.update_ysws_project_submission(project_id, {
            'Status': 'Rejected',
            'Decision Reason': admin_notes or f'Rejected by {current_user.username}'
        })

        if success:
            create_audit_log(
                action_type='project_rejection',
                description=f'Admin {current_user.username} rejected project {project_id}',
                user=current_user,
                target_type='project',
                target_id=project_id,
                severity='info',
                admin_action=True,
                category='admin'
            )
            message = 'Project rejected'
        else:
            return jsonify({'error': 'Failed to reject project'}), 500

    return jsonify({
        'success': True,
        'message': message
    })


@api_bp.route('/projects/delete/<string:project_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_project(project_id):
    """Delete a project submission from Airtable (admin only)"""
    from app.services.airtable import AirtableService

    airtable_service = AirtableService()
    current_user = get_current_user()

    success = airtable_service.delete_ysws_project_submission(project_id)

    if success:
        create_audit_log(
            action_type='project_delete',
            description=f'Admin {current_user.username} deleted project {project_id}',
            user=current_user,
            target_type='project',
            target_id=project_id,
            severity='warning',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Project deleted'
        })
    else:
        return jsonify({'error': 'Failed to delete project'}), 500


@api_bp.route('/projects/grant-override/<string:project_id>', methods=['PUT', 'POST'])
@login_required
@admin_required
def grant_override_project(project_id):
    """Override grant amount for a project in Airtable (admin only)"""
    from app.services.airtable import AirtableService

    airtable_service = AirtableService()
    current_user = get_current_user()

    data = request.get_json()
    grant_amount = float(data.get('grantAmount') or data.get('grant_amount', 0))
    override_reason = sanitize_string(data.get('overrideReason') or data.get('override_reason', ''), max_length=2000)

    if grant_amount < 0:
        return jsonify({'error': 'Grant amount cannot be negative'}), 400

    success = airtable_service.update_ysws_project_submission(project_id, {
        'Grant Amount Override': grant_amount,
        'Grant Override Reason': override_reason or f'Override by {current_user.username}'
    })

    if success:
        create_audit_log(
            action_type='project_override',
            description=f'Admin {current_user.username} set grant override to ${grant_amount} for project {project_id}',
            user=current_user,
            target_type='project',
            target_id=project_id,
            details={'grant_amount': grant_amount},
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'success': True,
            'message': 'Grant amount override set successfully'
        })
    else:
        return jsonify({'error': 'Failed to update grant override'}), 500
@api_bp.route('/status/incidents', methods=['GET'])
def get_public_status_incidents():
    """Get public status incidents (no auth required)"""
    from app.models.system import StatusIncident

    status_filter = request.args.get('status')
    limit = request.args.get('limit', 20, type=int)
    limit = min(limit, 100)

    query = StatusIncident.query

    if status_filter:
        query = query.filter(StatusIncident.status == status_filter)

    incidents = query.order_by(StatusIncident.created_at.desc()).limit(limit).all()
    incidents_data = [incident.to_dict() for incident in incidents]

    return jsonify({
        'incidents': incidents_data,
        'total': len(incidents_data)
    })


@api_bp.route('/status/incidents/<int:incident_id>', methods=['GET'])
def get_public_status_incident(incident_id):
    """Get a single public status incident (no auth required)"""
    from app.models.system import StatusIncident

    incident = StatusIncident.query.get_or_404(incident_id)

    return jsonify({
        'incident': incident.to_dict()
    })
@api_bp.route('/upload-images', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def upload_images():
    """Upload images to Hack Club CDN (supports both FormData and JSON base64)"""
    from app.utils.cdn_helpers import upload_to_hackclub_cdn, parse_base64_images
    from werkzeug.utils import secure_filename
    import os

    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401

    image_data_list = []
    max_size = 10 * 1024 * 1024  # 10MB per image
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

    if request.is_json:
        data = request.get_json()
        images = data.get('images', [])

        if not images:
            return jsonify({'error': 'No images provided'}), 400

        if len(images) > 20:
            return jsonify({'error': 'Maximum 20 images allowed per upload'}), 400

        image_data_list = parse_base64_images(images, max_size=max_size)

    else:
        if 'images' not in request.files:
            return jsonify({'error': 'No images provided'}), 400

        files = request.files.getlist('images')
        if not files:
            return jsonify({'error': 'No images provided'}), 400

        if len(files) > 20:
            return jsonify({'error': 'Maximum 20 images allowed per upload'}), 400

        for file in files:
            if file.filename == '':
                continue

            filename = secure_filename(file.filename)
            if '.' not in filename:
                continue

            ext = '.' + filename.rsplit('.', 1)[1].lower()
            if ext[1:] not in allowed_extensions:
                continue

            try:
                file.seek(0)
                image_data = file.read()

                if len(image_data) > max_size:
                    current_app.logger.warning(f'File {filename} too large')
                    continue

                image_data_list.append((image_data, ext))

            except Exception as e:
                current_app.logger.error(f'Error processing file {filename}: {str(e)}')
                continue

    if not image_data_list:
        return jsonify({'error': 'No valid images were processed'}), 400

    success, result = upload_to_hackclub_cdn(image_data_list)

    if not success:
        return jsonify({'error': result}), 500

    cdn_urls = result

    create_audit_log(
        action_type='images_upload',
        description=f'User {user.username} uploaded {len(cdn_urls)} images to CDN',
        user=user,
        target_type='upload',
        details={'image_count': len(cdn_urls)},
        category='user'
    )

    return jsonify({
        'success': True,
        'message': f'{len(cdn_urls)} images uploaded successfully',
        'urls': cdn_urls
    })
@api_bp.route('/v1/analytics/overview', methods=['GET'])
@login_required
def analytics_overview():
    """Get analytics overview - PLACEHOLDER"""
    return jsonify({
        'views': 0,
        'unique_visitors': 0,
        'message': 'Analytics not yet implemented'
    })
@api_bp.route('/clubs/<int:club_id>/posts', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_posts(club_id):
    """Get or create club posts"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin

    if not is_leader and not is_co_leader and not is_member and not is_admin_access:
        return jsonify({'error': 'Unauthorized'}), 403

    if is_admin_access:
        is_leader = True

    if request.method == 'POST':
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can create posts'}), 403

        data = request.get_json()
        content = data.get('content')

        if not content:
            return jsonify({'error': 'Content is required'}), 400

        valid, result = validate_input_with_security(content, "club_post", current_user, max_length=5000,
                                                     app=current_app)
        if not valid:
            return jsonify({'error': result}), 403

        if is_leader or is_co_leader:
            markdown_content = sanitize_string(result, max_length=5000, allow_html=False)
            html_content = markdown_to_html(markdown_content)
        else:
            markdown_content = sanitize_string(result, max_length=5000, allow_html=False)
            html_content = html.escape(markdown_content).replace('\n', '<br>')

        if not markdown_content.strip():
            return jsonify({'error': 'Content cannot be empty after sanitization'}), 400

        post = ClubPost(
            club_id=club_id,
            user_id=current_user.id,
            content=markdown_content,
            content_html=html_content
        )
        db.session.add(post)
        db.session.commit()

        create_audit_log(
            action_type='create_post',
            description=f"User {current_user.username} created a post in {club.name}",
            user=current_user,
            target_type='club',
            target_id=club_id,
            details={
                'club_name': club.name,
                'post_id': post.id,
                'content_length': len(markdown_content)
            },
            category='club'
        )

        return jsonify({'message': 'Post created successfully'})

    posts = ClubPost.query.filter_by(club_id=club_id).order_by(ClubPost.created_at.desc()).all()
    posts_data = []

    for post in posts:
        try:
            content_html = post.content_html
            if not content_html:
                content_html = html.escape(post.content).replace('\n', '<br>')

            post_data = {
                'id': post.id,
                'content': post.content,  # Raw markdown content
                'content_html': content_html,  # HTML content for display
                'created_at': post.created_at.isoformat(),
                'user': {
                    'id': post.user.id,
                    'username': post.user.username
                }
            }
            posts_data.append(post_data)
        except Exception as e:
            current_app.logger.error(f"Error processing post {post.id}: {e}")
            continue

    return jsonify({'posts': posts_data})


@api_bp.route('/clubs/<int:club_id>/posts/<int:post_id>', methods=['DELETE'])
@login_required
@limiter.limit("100 per hour")
def delete_club_post(club_id, post_id):
    """Delete a club post"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    post = ClubPost.query.get_or_404(post_id)

    if post.club_id != club_id:
        return jsonify({'error': 'Post not found in this club'}), 404

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_post_author = post.user_id == current_user.id

    if not is_leader and not is_co_leader and not is_post_author and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(post)
    db.session.commit()

    create_audit_log(
        action_type='delete_post',
        description=f"User {current_user.username} deleted a post in {club.name}",
        user=current_user,
        target_type='club',
        target_id=club_id,
        category='club'
    )

    return jsonify({'message': 'Post deleted successfully'})


@api_bp.route('/clubs/<int:club_id>/assignments', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_assignments(club_id):
    """Get or create club assignments"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders can create assignments'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        due_date = data.get('due_date')

        if not title or not description:
            return jsonify({'error': 'Title and description are required'}), 400

        valid, result = validate_input_with_security(title, "assignment_title", current_user, max_length=200, app=current_app)
        if not valid:
            return jsonify({'error': result}), 403
        title = result

        valid, result = validate_input_with_security(description, "assignment_description", current_user, max_length=2000, app=current_app)
        if not valid:
            return jsonify({'error': result}), 403
        description = result

        assignment = ClubAssignment(
            club_id=club_id,
            title=title,
            description=description,
            due_date=due_date
        )
        db.session.add(assignment)
        db.session.commit()

        create_audit_log(
            action_type='create_assignment',
            description=f"User {current_user.username} created assignment '{title}' in {club.name}",
            user=current_user,
            target_type='club',
            target_id=club_id,
            category='club'
        )

        return jsonify({'message': 'Assignment created successfully', 'assignment_id': assignment.id})

    assignments = ClubAssignment.query.filter_by(club_id=club_id).order_by(ClubAssignment.due_date.desc()).all()
    assignments_data = [{
        'id': a.id,
        'title': a.title,
        'description': a.description,
        'due_date': a.due_date.isoformat() if a.due_date else None,
        'created_at': a.created_at.isoformat() if a.created_at else None
    } for a in assignments]

    return jsonify({'assignments': assignments_data})


@api_bp.route('/clubs/<int:club_id>/assignments/<int:assignment_id>', methods=['DELETE'])
@login_required
@limiter.limit("100 per hour")
def delete_club_assignment(club_id, assignment_id):
    """Delete a club assignment"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    assignment = ClubAssignment.query.get_or_404(assignment_id)

    if assignment.club_id != club_id:
        return jsonify({'error': 'Assignment not found in this club'}), 404

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)

    if not is_leader and not is_co_leader and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(assignment)
    db.session.commit()

    return jsonify({'message': 'Assignment deleted successfully'})


@api_bp.route('/clubs/<int:club_id>/meetings', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_meetings(club_id):
    """Get or create club meetings"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders can create meetings'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        meeting_date = data.get('meeting_date')
        location = data.get('location')

        if not title:
            return jsonify({'error': 'Title is required'}), 400

        valid, result = validate_input_with_security(title, "meeting_title", current_user, max_length=200, app=current_app)
        if not valid:
            return jsonify({'error': result}), 403
        title = result

        if description:
            valid, result = validate_input_with_security(description, "meeting_description", current_user, max_length=2000, app=current_app)
            if not valid:
                return jsonify({'error': result}), 403
            description = result

        meeting = ClubMeeting(
            club_id=club_id,
            title=title,
            description=description,
            meeting_date=meeting_date,
            location=location
        )
        db.session.add(meeting)
        db.session.commit()

        create_audit_log(
            action_type='create_meeting',
            description=f"User {current_user.username} created meeting '{title}' in {club.name}",
            user=current_user,
            target_type='club',
            target_id=club_id,
            category='club'
        )

        return jsonify({'message': 'Meeting created successfully', 'meeting_id': meeting.id})

    meetings = ClubMeeting.query.filter_by(club_id=club_id).order_by(ClubMeeting.meeting_date.desc()).all()
    meetings_data = [{
        'id': m.id,
        'title': m.title,
        'description': m.description,
        'meeting_date': m.meeting_date.isoformat() if m.meeting_date else None,
        'location': m.location,
        'created_at': m.created_at.isoformat() if m.created_at else None
    } for m in meetings]

    return jsonify({'meetings': meetings_data})


@api_bp.route('/clubs/<int:club_id>/meetings/<int:meeting_id>', methods=['DELETE'])
@login_required
@limiter.limit("100 per hour")
def delete_club_meeting(club_id, meeting_id):
    """Delete a club meeting"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    meeting = ClubMeeting.query.get_or_404(meeting_id)

    if meeting.club_id != club_id:
        return jsonify({'error': 'Meeting not found in this club'}), 404

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)

    if not is_leader and not is_co_leader and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(meeting)
    db.session.commit()

    return jsonify({'message': 'Meeting deleted successfully'})


@api_bp.route('/clubs/<int:club_id>/resources', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_resources(club_id):
    """Get or create club resources"""
    from app.models.club_content import ClubResource
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders can create resources'}), 403

        data = request.get_json()
        title = data.get('title')
        url = data.get('url')
        description = data.get('description')
        icon = data.get('icon', 'book')

        if not title or not url:
            return jsonify({'error': 'Title and URL are required'}), 400

        from app.utils.security import validate_input_with_security
        from flask import current_app

        valid, result = validate_input_with_security(title, "resource_title", current_user, max_length=200, app=current_app)
        if not valid:
            return jsonify({'error': result}), 403
        title = result

        valid, result = validate_input_with_security(url, "resource_url", current_user, max_length=500, app=current_app)
        if not valid:
            return jsonify({'error': result}), 403
        url = result

        if description:
            valid, result = validate_input_with_security(description, "resource_description", current_user, max_length=2000, app=current_app)
            if not valid:
                return jsonify({'error': result}), 403
            description = result

        resource = ClubResource(
            club_id=club_id,
            title=title,
            url=url,
            description=description,
            icon=icon
        )
        db.session.add(resource)
        db.session.commit()

        create_audit_log(
            action_type='create_resource',
            description=f"User {current_user.username} created resource '{title}' in {club.name}",
            user=current_user,
            target_type='club',
            target_id=club_id,
            category='club'
        )

        return jsonify({'message': 'Resource created successfully', 'resource_id': resource.id})

    resources = ClubResource.query.filter_by(club_id=club_id).order_by(ClubResource.created_at.desc()).all()
    resources_data = [{
        'id': r.id,
        'title': r.title,
        'url': r.url,
        'description': r.description,
        'icon': r.icon,
        'created_at': r.created_at.isoformat() if r.created_at else None
    } for r in resources]

    return jsonify({'resources': resources_data})


@api_bp.route('/clubs/<int:club_id>/resources/<int:resource_id>', methods=['DELETE'])
@login_required
@limiter.limit("100 per hour")
def delete_club_resource(club_id, resource_id):
    """Delete a club resource"""
    from app.models.club_content import ClubResource
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    resource = ClubResource.query.get_or_404(resource_id)

    if resource.club_id != club_id:
        return jsonify({'error': 'Resource not found in this club'}), 404

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)

    if not is_leader and not is_co_leader and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(resource)
    db.session.commit()

    create_audit_log(
        action_type='delete_resource',
        description=f"User {current_user.username} deleted resource '{resource.title}' in {club.name}",
        user=current_user,
        target_type='club',
        target_id=club_id,
        category='club'
    )

    return jsonify({'message': 'Resource deleted successfully'})


@api_bp.route('/clubs/<int:club_id>/transactions', methods=['GET'])
@login_required
@limiter.limit("500 per hour")
def club_transactions(club_id):
    """Get club transaction history"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)

    transactions_pagination = ClubTransaction.query.filter_by(club_id=club_id).order_by(
        ClubTransaction.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    transactions_data = []
    for t in transactions_pagination.items:
        transactions_data.append({
            'id': t.id,
            'transaction_type': t.transaction_type,
            'amount': t.amount,
            'description': t.description,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'reference_type': t.reference_type,
            'reference_id': t.reference_id
        })

    return jsonify({
        'transactions': transactions_data,
        'total': transactions_pagination.total,
        'page': page,
        'per_page': per_page,
        'pages': transactions_pagination.pages
    })


@api_bp.route('/club/<int:club_id>/quests', methods=['GET'])
@login_required
@limiter.limit("500 per hour")
def club_quests(club_id):
    """Get club quests and progress"""
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    if not is_member and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    quests = ClubQuestProgress.query.filter_by(club_id=club_id).all()
    quests_data = [{
        'id': q.id,
        'quest_type': q.quest.quest_type if q.quest else 'unknown',
        'quest_name': q.quest.name if q.quest else 'Unknown Quest',
        'quest_description': q.quest.description if q.quest else '',
        'progress': q.progress,
        'goal': q.target,
        'reward': q.quest.reward_tokens if q.quest else 0,
        'completed': q.completed,
        'reward_claimed': q.reward_claimed,
        'completed_at': q.completed_at.isoformat() if q.completed_at else None
    } for q in quests]

    return jsonify({'quests': quests_data})
@api_bp.route('/gallery/posts', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
def gallery_posts():
    """Get or create gallery posts"""
    if request.method == 'POST':
        if not is_authenticated():
            return jsonify({'error': 'Authentication required'}), 401

        current_user = get_current_user()
        data = request.get_json()

        club_id = data.get('club_id')
        title = data.get('title')
        description = data.get('description')
        images = data.get('images', [])
        custom_club_name = data.get('custom_club_name')  # Admin override for club name

        if not club_id or not title or not description:
            return jsonify({'error': 'Club ID, title, and description are required'}), 400

        if len(images) > 50:
            images = images[:50]

        club = Club.query.get_or_404(club_id)
        is_leader = club.leader_id == current_user.id
        is_co_leader = is_user_co_leader(club, current_user)

        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders can create gallery posts'}), 403

        valid, result = validate_input_with_security(title, "gallery_title", current_user, max_length=200, app=current_app)
        if not valid:
            return jsonify({'error': result}), 403
        title = result

        valid, result = validate_input_with_security(description, "gallery_description", current_user, max_length=2000, app=current_app)
        if not valid:
            return jsonify({'error': result}), 403
        description = result

        post = GalleryPost(
            club_id=club_id,
            user_id=current_user.id,
            title=title,
            description=description
        )
        post.set_images(images)

        update_quest_progress(club_id, 'gallery_post', 1)

        if current_user.is_admin and custom_club_name:
            valid, result = validate_input_with_security(custom_club_name, "custom_club_name", current_user, max_length=100, app=current_app)
            if not valid:
                return jsonify({'error': result}), 403
            post.description = f"[CUSTOM_CLUB:{result}] {description}"

        db.session.add(post)
        db.session.commit()

        current_app.logger.info(f"Gallery post created: ID={post.id}, title='{title}', club_id={club_id}, images={len(images)}")

        try:
            airtable_success = airtable_service.log_gallery_post(
                post_title=title,
                description=description,
                photos=images,
                club_name=club.name,
                author_username=current_user.username
            )
            if airtable_success:
                current_app.logger.info(f"Gallery post {post.id} successfully logged to Airtable")
            else:
                current_app.logger.warning(f"Failed to log gallery post {post.id} to Airtable")
        except Exception as e:
            current_app.logger.error(f"Exception logging gallery post {post.id} to Airtable: {str(e)}")

        create_audit_log(
            action_type='gallery_post_create',
            description=f"User {current_user.username} created gallery post '{title}' for club '{club.name}'",
            user=current_user,
            target_type='club',
            target_id=str(club_id),
            details={
                'post_title': title,
                'club_name': club.name,
                'image_count': len(images),
                'custom_club_name': custom_club_name if current_user.is_admin and custom_club_name else None
            },
            severity='info',
            admin_action=current_user.is_admin and custom_club_name,
            category='gallery'
        )

        return jsonify({'message': 'Gallery post created successfully', 'post_id': post.id})

    try:
        posts = GalleryPost.query.order_by(GalleryPost.created_at.desc()).all()
        posts_data = []

        current_app.logger.info(f"Retrieved {len(posts)} gallery posts from database")

        for post in posts:
            try:
                club = Club.query.get(post.club_id)
                user = User.query.get(post.user_id)

                if not club or not user:
                    current_app.logger.warning(f"Skipping post {post.id}: missing club ({club}) or user ({user})")
                    continue

                display_club_name = club.name
                display_description = post.description

                if post.description.startswith('[CUSTOM_CLUB:'):
                    try:
                        end_idx = post.description.find('] ')
                        if end_idx != -1:
                            custom_club_name = post.description[13:end_idx]  # Skip '[CUSTOM_CLUB:'
                            display_club_name = custom_club_name
                            display_description = post.description[end_idx + 2:]  # Skip '] '
                    except:
                        pass  # Fall back to original if parsing fails

                post_data = {
                    'id': post.id,
                    'title': post.title,
                    'description': display_description,
                    'images': post.get_images(),
                    'club_name': display_club_name,
                    'club': {
                        'id': club.id,
                        'name': display_club_name,
                        'location': club.location or ''
                    },
                    'author': {
                        'id': user.id,
                        'username': user.username
                    },
                    'created_at': post.created_at.isoformat() if post.created_at else '',
                    'featured': bool(post.featured)
                }
                posts_data.append(post_data)
                current_app.logger.debug(f"Gallery post {post.id}: '{post.title}' by {user.username} from {club.name}, {len(post.get_images())} images")

            except Exception as e:
                current_app.logger.error(f"Error processing gallery post {post.id}: {str(e)}")
                continue

        current_app.logger.info(f"Returning {len(posts_data)} gallery posts to frontend")
        return jsonify({'posts': posts_data})

    except Exception as e:
        current_app.logger.error(f"Error fetching gallery posts: {str(e)}")
        db.session.rollback()
        return jsonify({'posts': []})


@api_bp.route('/gallery/posts/<int:post_id>', methods=['DELETE'])
@login_required
@limiter.limit("50 per hour")
def delete_gallery_post(post_id):
    """Delete a gallery post"""
    current_user = get_current_user()

    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    post = GalleryPost.query.get_or_404(post_id)

    try:
        images = post.get_images()
        post_title = post.title
        post_author_name = post.user.username if post.user else 'Unknown'
        club_name = post.club.name if post.club else 'Unknown'
        club = post.club

        if club and club.tokens >= 100:
            success, error_msg = create_club_transaction(
                club_id=club.id,
                transaction_type='debit',
                amount=-100,  # Negative amount for deduction
                description=f'Gallery post deletion penalty: "{post_title}"',
                user_id=current_user.id,
                reference_type='gallery_post_deletion',
                reference_id=post_id,
                created_by=current_user.id
            )

            if not success:
                current_app.logger.warning(f"Failed to deduct tokens for gallery post deletion: {error_msg}")

        db.session.delete(post)
        db.session.commit()

        create_audit_log(
            action_type='gallery_post_delete',
            description=f"Admin {current_user.username} deleted gallery post '{post_title}' by {post_author_name}",
            user=current_user,
            target_type='gallery_post',
            target_id=str(post_id),
            details={
                'post_title': post_title,
                'club_name': club_name,
                'author': post_author_name,
                'image_count': len(images),
                'token_penalty': 100 if club and club.tokens >= 100 else 0
            },
            severity='warning',
            admin_action=True,
            category='gallery'
        )

        current_app.logger.info(f"Gallery post {post_id} deleted by admin {current_user.username}")
        return jsonify({'message': 'Gallery post deleted successfully'})

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting gallery post {post_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete gallery post'}), 500


@api_bp.route('/projects/review/test', methods=['GET'])
def api_test_projects():
    """Test endpoint - no auth required"""
    return jsonify({
        'success': True,
        'message': 'Test successful',
        'projects': [
            {'id': '1', 'firstName': 'Test', 'lastName': 'User', 'status': 'Approved'},
            {'id': '2', 'firstName': 'Another', 'lastName': 'Test', 'status': 'Rejected'}
        ]
    })


# Proxy endpoints for poster editor - keep API keys server-side
@api_bp.route('/fonts/google', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def proxy_google_fonts():
    """Proxy Google Fonts API to keep API key server-side"""
    api_key = current_app.config.get('GOOGLE_FONTS_API_KEY')
    if not api_key:
        return jsonify({'error': 'Google Fonts API not configured'}), 503

    try:
        sort = request.args.get('sort', 'popularity')
        response = http_requests.get(
            f'https://www.googleapis.com/webfonts/v1/webfonts',
            params={'key': api_key, 'sort': sort},
            timeout=10
        )

        if response.status_code == 200:
            return jsonify(response.json())
        else:
            current_app.logger.error(f"Google Fonts API error: {response.status_code}")
            return jsonify({'error': 'Failed to fetch fonts'}), response.status_code

    except Exception as e:
        current_app.logger.error(f"Error proxying Google Fonts API: {str(e)}")
        return jsonify({'error': 'Failed to fetch fonts'}), 500


@api_bp.route('/images/search', methods=['GET'])
@login_required
@limiter.limit("50 per hour")
def proxy_unsplash_search():
    """Proxy Unsplash API to keep API key server-side"""
    api_key = current_app.config.get('UNSPLASH_API_KEY')
    if not api_key:
        return jsonify({'error': 'Image search API not configured'}), 503

    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Query parameter required'}), 400

    try:
        per_page = min(int(request.args.get('per_page', 20)), 30)  # Max 30 for safety

        response = http_requests.get(
            'https://api.unsplash.com/search/photos',
            params={
                'query': query,
                'per_page': per_page,
                'client_id': api_key
            },
            timeout=10
        )

        if response.status_code == 200:
            return jsonify(response.json())
        else:
            current_app.logger.error(f"Unsplash API error: {response.status_code}")
            return jsonify({'error': 'Failed to search images'}), response.status_code

    except Exception as e:
        current_app.logger.error(f"Error proxying Unsplash API: {str(e)}")
        return jsonify({'error': 'Failed to search images'}), 500


# Export endpoints
@api_bp.route('/admin/export/users', methods=['GET'])
@login_required
@permission_required('users.view')
def export_users():
    """Export all users as JSON (requires users.view permission)"""
    from datetime import datetime, timezone
    current_user = get_current_user()

    try:
        users = User.query.all()
        users_data = []

        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'is_admin': user.is_admin,
                'is_suspended': user.is_suspended,
                'totp_enabled': user.totp_enabled,
                'roles': [role.name for role in user.roles]
            })

        # Log export action
        create_audit_log(
            action_type='users_export',
            description=f'Admin {current_user.username} exported {len(users_data)} users',
            user=current_user,
            severity='info',
            category='admin',
            admin_action=True,
            details={'count': len(users_data)}
        )

        return jsonify({
            'success': True,
            'count': len(users_data),
            'data': users_data,
            'exported_at': datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error exporting users: {str(e)}")
        return jsonify({'error': 'Failed to export users'}), 500


@api_bp.route('/admin/export/clubs', methods=['GET'])
@login_required
@permission_required('clubs.view')
def export_clubs():
    """Export all clubs as JSON (requires clubs.view permission)"""
    from datetime import datetime, timezone
    current_user = get_current_user()

    try:
        clubs = Club.query.all()
        clubs_data = []

        for club in clubs:
            leader = User.query.get(club.leader_id) if club.leader_id else None
            co_leader = User.query.get(club.co_leader_id) if club.co_leader_id else None
            member_count = ClubMembership.query.filter_by(club_id=club.id).count()

            clubs_data.append({
                'id': club.id,
                'name': club.name,
                'description': club.description,
                'location': club.location,
                'created_at': club.created_at.isoformat() if club.created_at else None,
                'leader': leader.username if leader else None,
                'leader_email': leader.email if leader else None,
                'co_leader': co_leader.username if co_leader else None,
                'balance': float(club.balance),
                'tokens': club.tokens,
                'member_count': member_count,
                'join_code': club.join_code,
                'is_suspended': club.is_suspended,
                'sync_immune': club.sync_immune
            })

        # Log export action
        create_audit_log(
            action_type='clubs_export',
            description=f'Admin {current_user.username} exported {len(clubs_data)} clubs',
            user=current_user,
            severity='info',
            category='admin',
            admin_action=True,
            details={'count': len(clubs_data)}
        )

        return jsonify({
            'success': True,
            'count': len(clubs_data),
            'data': clubs_data,
            'exported_at': datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error exporting clubs: {str(e)}")
        return jsonify({'error': 'Failed to export clubs'}), 500


@api_bp.route('/admin/export/audit-logs', methods=['GET'])
@login_required
@permission_required('admin.view_activity')
def export_audit_logs():
    """Export all audit logs as JSON (requires admin.view_activity permission)"""
    from app.models.user import AuditLog
    from datetime import datetime, timezone
    current_user = get_current_user()

    try:
        audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
        logs_data = []

        for log in audit_logs:
            log_user = User.query.get(log.user_id) if log.user_id else None

            logs_data.append({
                'id': log.id,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'user_id': log.user_id,
                'username': log_user.username if log_user else None,
                'action_type': log.action_type,
                'action_category': log.action_category,
                'target_type': log.target_type,
                'target_id': log.target_id,
                'description': log.description,
                'details': log.details,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'severity': log.severity,
                'admin_action': log.admin_action
            })

        # Log export action
        create_audit_log(
            action_type='audit_logs_export',
            description=f'Admin {current_user.username} exported {len(logs_data)} audit logs',
            user=current_user,
            severity='warning',
            category='admin',
            admin_action=True,
            details={'count': len(logs_data)}
        )

        return jsonify({
            'success': True,
            'count': len(logs_data),
            'data': logs_data,
            'exported_at': datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        current_app.logger.error(f"Error exporting audit logs: {str(e)}")
        return jsonify({'error': 'Failed to export audit logs'}), 500
