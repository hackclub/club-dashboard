"""
Admin routes blueprint for the Hack Club Dashboard.
Handles admin panel, user management, club management, order reviews, and system settings.
"""

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from datetime import datetime, timezone
from extensions import db
from app.decorators.auth import login_required, admin_required, reviewer_required, permission_required
from app.utils.auth_helpers import get_current_user
from app.utils.sanitization import sanitize_string
from app.models.user import User, Role, AuditLog
from app.models.club import Club, ClubMembership
from app.models.economy import ProjectSubmission, ClubTransaction
from app.models.system import SystemSettings
from app.services.airtable import AirtableService

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/')
@admin_bp.route('/dashboard')
@login_required
@permission_required('admin.access_dashboard')
def dashboard():
    """Admin dashboard - requires admin.access_dashboard permission"""
    from app.models.club_content import ClubPost, ClubAssignment

    current_user = get_current_user()

    # Log admin dashboard access
    from app.models.user import create_audit_log
    create_audit_log(
        action_type='admin_dashboard_access',
        description=f'Admin {current_user.username} accessed admin dashboard',
        user=current_user,
        severity='info',
        category='admin',
        admin_action=True
    )

    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()

    airtable_service = AirtableService()
    
    # Fetch Airtable projects and check connection status
    airtable_status = 'operational'
    airtable_error = None
    all_projects = []
    
    try:
        all_projects = airtable_service.get_ysws_project_submissions()
        airtable_status = 'operational'
    except Exception as e:
        airtable_status = 'error'
        airtable_error = str(e)
        all_projects = []

    # Count projects by status
    pending_projects = len([p for p in all_projects if p.get('status', '').lower() in ['pending', '']])
    total_pending_projects = pending_projects
    total_approved_projects = len([p for p in all_projects if p.get('status', '').lower() == 'approved'])
    total_rejected_projects = len([p for p in all_projects if p.get('status', '').lower() in ['rejected', 'denied']])
    total_projects = len(all_projects)

    # Calculate hours statistics
    approved_projects = [p for p in all_projects if p.get('status', '').lower() == 'approved']
    approved_hours = 0
    for project in approved_projects:
        hours = project.get('hours', 0)
        try:
            approved_hours += float(hours) if hours else 0
        except (ValueError, TypeError):
            pass

    submitted_hours = 0
    for project in all_projects:
        hours = project.get('hours', 0)
        try:
            submitted_hours += float(hours) if hours else 0
        except (ValueError, TypeError):
            pass

    # Calculate weighted grants (hours / 10)
    total_approved_weighted_grants = round(approved_hours / 10, 2)
    total_submitted_weighted_grants = round(submitted_hours / 10, 2)

    # Calculate averages
    avg_hours_per_project = round(submitted_hours / total_projects, 2) if total_projects > 0 else 0
    avg_hours_approved = round(approved_hours / total_approved_projects, 2) if total_approved_projects > 0 else 0

    # Calculate approval rate
    approval_rate = round((total_approved_projects / total_projects * 100), 1) if total_projects > 0 else 0

    total_club_balance = db.session.query(db.func.sum(Club.balance)).scalar() or 0

    # Calculate users to clubs ratio
    users_to_clubs_ratio = round(total_users / total_clubs, 2) if total_clubs > 0 else 0

    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_clubs = Club.query.order_by(Club.created_at.desc()).limit(10).all()

    can_view_users = current_user.has_permission('users.view') or current_user.is_admin
    can_create_users = current_user.has_permission('users.create') or current_user.is_admin
    can_view_clubs = current_user.has_permission('clubs.view') or current_user.is_admin
    can_view_content = current_user.has_permission('content.view') or current_user.is_admin
    can_manage_roles = current_user.has_permission('system.manage_roles') or current_user.has_role('super-admin')
    can_manage_users = current_user.has_permission('users.assign_roles') or current_user.is_admin
    can_manage_settings = current_user.has_permission('system.manage_settings') or current_user.is_admin
    can_view_dashboard = current_user.has_permission('admin.access_dashboard') or current_user.is_admin
    can_view_activity = current_user.has_permission('admin.view_activity') or current_user.is_admin

    user_permissions = current_user.get_all_permissions()

    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_clubs=total_clubs,
                         total_posts=total_posts,
                         total_assignments=total_assignments,
                         total_projects=total_projects,
                         pending_projects=pending_projects,
                         total_pending_projects=total_pending_projects,
                         total_approved_projects=total_approved_projects,
                         total_rejected_projects=total_rejected_projects,
                         total_approved_weighted_grants=total_approved_weighted_grants,
                         total_submitted_weighted_grants=total_submitted_weighted_grants,
                         approved_hours=approved_hours,
                         submitted_hours=submitted_hours,
                         avg_hours_per_project=avg_hours_per_project,
                         avg_hours_approved=avg_hours_approved,
                         approval_rate=approval_rate,
                         total_club_balance=total_club_balance,
                         users_to_clubs_ratio=users_to_clubs_ratio,
                         airtable_status=airtable_status,
                         airtable_error=airtable_error,
                         recent_users=recent_users,
                         recent_clubs=recent_clubs,
                         can_view_users=can_view_users,
                         can_create_users=can_create_users,
                         can_view_clubs=can_view_clubs,
                         can_view_content=can_view_content,
                         can_manage_roles=can_manage_roles,
                         can_manage_users=can_manage_users,
                         can_manage_settings=can_manage_settings,
                         can_view_dashboard=can_view_dashboard,
                         can_view_activity=can_view_activity,
                         user_permissions=user_permissions)


@admin_bp.route('/users')
@login_required
@permission_required('users.view')
def users():
    """User management - returns HTML"""
    page = request.args.get('page', 1, type=int)
    per_page = 50

    search = request.args.get('search', '')
    if search:
        search_term = f"%{search}%"
        users_query = User.query.filter(
            db.or_(
                User.username.ilike(search_term),
                User.email.ilike(search_term),
                User.first_name.ilike(search_term),
                User.last_name.ilike(search_term)
            )
        )
    else:
        users_query = User.query

    users_pagination = users_query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('admin_users.html',
                         users=users_pagination.items,
                         pagination=users_pagination,
                         search=search)


@admin_bp.route('/users/<int:user_id>')
@login_required
@permission_required('users.view')
def user_detail(user_id):
    """View user details"""
    user = User.query.get_or_404(user_id)

    memberships = ClubMembership.query.filter_by(user_id=user_id).all()
    clubs = [m.club for m in memberships]

    audit_logs = AuditLog.query.filter_by(user_id=user_id).order_by(
        AuditLog.timestamp.desc()
    ).limit(50).all()

    return render_template('admin_user_detail.html',
                         user=user,
                         clubs=clubs,
                         audit_logs=audit_logs)


@admin_bp.route('/users/<int:user_id>/suspend', methods=['POST'])
@login_required
@permission_required('users.suspend')
def suspend_user(user_id):
    """Suspend a user"""
    user = User.query.get_or_404(user_id)

    if user.is_admin:
        flash('Cannot suspend admin users.', 'error')
        return redirect(url_for('admin.user_detail', user_id=user_id))

    reason = sanitize_string(request.form.get('reason', ''), max_length=500)

    user.is_suspended = True
    db.session.commit()

    from app.models.user import AuditLog
    audit_log = AuditLog(
        user_id=get_current_user().id,
        action_type='user_suspended',
        description=f'Suspended user: {user.username}',
        target_type='user',
        target_id=user_id,
        details={'reason': reason},
        severity='warning',
        category='admin'
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'User {user.username} has been suspended.', 'success')
    return redirect(url_for('admin.user_detail', user_id=user_id))


@admin_bp.route('/users/<int:user_id>/unsuspend', methods=['POST'])
@login_required
@permission_required('users.suspend')
def unsuspend_user(user_id):
    """Unsuspend a user"""
    user = User.query.get_or_404(user_id)

    user.is_suspended = False
    db.session.commit()

    audit_log = AuditLog(
        user_id=get_current_user().id,
        action_type='user_unsuspended',
        description=f'Unsuspended user: {user.username}',
        target_type='user',
        target_id=user_id,
        severity='info',
        category='admin'
    )
    db.session.add(audit_log)
    db.session.commit()

    flash(f'User {user.username} has been unsuspended.', 'success')
    return redirect(url_for('admin.user_detail', user_id=user_id))


@admin_bp.route('/users/recent')
@login_required
@permission_required('users.view')
def recent_users():
    """Get the 10 most recent users"""
    users = User.query.order_by(User.created_at.desc()).limit(10).all()

    results = [{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'first_name': u.first_name,
        'last_name': u.last_name,
        'is_admin': u.is_admin,
        'is_suspended': u.is_suspended,
        'totp_enabled': u.totp_enabled,
        'created_at': u.created_at.isoformat() if u.created_at else None,
        'clubs_led': ClubMembership.query.filter_by(user_id=u.id, role='leader').count(),
        'clubs_joined': ClubMembership.query.filter(ClubMembership.user_id == u.id, ClubMembership.role != 'leader').count()
    } for u in users]

    return jsonify({'results': results})


@admin_bp.route('/search/users')
@login_required
@permission_required('users.view')
def search_users():
    """Search users by username or email"""
    query = request.args.get('q', '').strip()

    if not query:
        return jsonify({'results': []})

    search_term = f"%{query}%"
    users = User.query.filter(
        db.or_(
            User.username.ilike(search_term),
            User.email.ilike(search_term),
            User.first_name.ilike(search_term),
            User.last_name.ilike(search_term)
        )
    ).limit(50).all()

    results = [{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'first_name': u.first_name,
        'last_name': u.last_name,
        'is_admin': u.is_admin,
        'is_suspended': u.is_suspended,
        'totp_enabled': u.totp_enabled,
        'created_at': u.created_at.isoformat() if u.created_at else None,
        'clubs_led': ClubMembership.query.filter_by(user_id=u.id, role='leader').count(),
        'clubs_joined': ClubMembership.query.filter(ClubMembership.user_id == u.id, ClubMembership.role != 'leader').count()
    } for u in users]

    return jsonify({'results': results})


@admin_bp.route('/clubs/recent')
@login_required
@permission_required('clubs.view')
def recent_clubs():
    """Get the 10 most recent clubs"""
    clubs = Club.query.order_by(Club.created_at.desc()).limit(10).all()

    results = []
    for c in clubs:
        leader_user = c.leader if c.leader_id else None

        member_count = ClubMembership.query.filter_by(club_id=c.id).count()

        results.append({
            'id': c.id,
            'name': c.name,
            'location': c.location,
            'balance': c.balance,
            'tokens': c.tokens,
            'is_suspended': c.is_suspended,
            'created_at': c.created_at.isoformat() if c.created_at else None,
            'leader': leader_user.username if leader_user else 'No Leader',
            'leader_email': leader_user.email if leader_user else 'N/A',
            'leader_id': leader_user.id if leader_user else None,
            'member_count': member_count,
            'sync_immune': c.sync_immune if hasattr(c, 'sync_immune') else False
        })

    return jsonify({'results': results})


@admin_bp.route('/search/clubs')
@login_required
@permission_required('clubs.view')
def search_clubs():
    """Search clubs by name - optionally includes Airtable-only clubs"""
    query = request.args.get('q', '').strip().lower()
    include_airtable = request.args.get('include_airtable', 'false').lower() == 'true'

    if not query:
        return jsonify({'results': []})

    search_term = f"%{query}%"
    clubs = Club.query.filter(Club.name.ilike(search_term)).limit(50).all()

    results = []
    dashboard_club_names = set()

    # Add dashboard clubs
    for c in clubs:
        leader_user = c.leader if c.leader_id else None
        member_count = ClubMembership.query.filter_by(club_id=c.id).count()

        results.append({
            'id': c.id,
            'name': c.name,
            'location': c.location,
            'balance': c.balance,
            'tokens': c.tokens,
            'is_suspended': c.is_suspended,
            'created_at': c.created_at.isoformat() if c.created_at else None,
            'leader': leader_user.username if leader_user else 'No Leader',
            'leader_email': leader_user.email if leader_user else 'N/A',
            'leader_id': leader_user.id if leader_user else None,
            'member_count': member_count,
            'sync_immune': c.sync_immune if hasattr(c, 'sync_immune') else False,
            'airtable_id': getattr(c, 'airtable_id', None),
            'is_airtable_only': False
        })
        dashboard_club_names.add(c.name.lower().strip())

    # Only search Airtable clubs if explicitly requested (resource intensive)
    if include_airtable:
        try:
            airtable_clubs = AirtableService().get_all_clubs()

            # Filter by search and exclude already-linked clubs
            for airtable_club in airtable_clubs:
                club_name = airtable_club['name'].lower().strip()

                # Check if matches search and isn't already in dashboard
                if (query in club_name or query in airtable_club['location'].lower()) and \
                   club_name not in dashboard_club_names:

                    results.append({
                        'id': None,
                        'name': airtable_club['name'],
                        'location': airtable_club['location'],
                        'balance': None,
                        'tokens': None,
                        'is_suspended': airtable_club['suspended'],
                        'created_at': None,
                        'leader': None,
                        'leader_email': airtable_club['leader_emails'],
                        'leader_id': None,
                        'member_count': None,
                        'sync_immune': False,
                        'airtable_id': airtable_club['airtable_id'],
                        'is_airtable_only': True
                    })

        except Exception as e:
            current_app.logger.error(f"Error fetching Airtable clubs in search: {str(e)}")

    return jsonify({'results': results})


@admin_bp.route('/clubs')
@login_required
@permission_required('clubs.view')
def clubs():
    """Club management - DEPRECATED: Use admin dashboard clubs tab instead"""
    # Redirect to admin dashboard with clubs tab
    return redirect(url_for('admin.dashboard') + '#clubs')


# @admin_bp.route('/clubs')
# @login_required
# @permission_required('clubs.view')
# def clubs():
#     """Club management - returns HTML"""
#     page = request.args.get('page', 1, type=int)
#     per_page = 50
#
#     search = request.args.get('search', '')
#     if search:
#         search_term = f"%{search}%"
#         clubs_query = Club.query.filter(Club.name.ilike(search_term))
#     else:
#         clubs_query = Club.query
#
#     clubs_pagination = clubs_query.order_by(Club.created_at.desc()).paginate(
#         page=page, per_page=per_page, error_out=False
#     )
#
#     return render_template('admin_clubs.html',
#                          clubs=clubs_pagination.items,
#                          pagination=clubs_pagination,
#                          search=search)


@admin_bp.route('/clubs/<int:club_id>')
@login_required
@permission_required('clubs.view')
def club_detail(club_id):
    """View club details"""
    club = Club.query.get_or_404(club_id)

    memberships = ClubMembership.query.filter_by(club_id=club_id).all()

    transactions = ClubTransaction.query.filter_by(club_id=club_id).order_by(
        ClubTransaction.created_at.desc()
    ).limit(50).all()

    return render_template('admin_club_detail.html',
                         club=club,
                         memberships=memberships,
                         transactions=transactions)


@admin_bp.route('/clubs/create', methods=['POST'])
@login_required
@permission_required('clubs.create')
def create_club():
    """Create a new club"""
    from app.models.user import create_audit_log

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    location = data.get('location', '').strip()
    leader_email = data.get('leader_email', '').strip().lower()
    balance = float(data.get('balance', 0))

    if not name:
        return jsonify({'error': 'Club name is required'}), 400

    if not leader_email:
        return jsonify({'error': 'Leader email is required'}), 400

    existing_club = Club.query.filter_by(name=name).first()
    if existing_club:
        return jsonify({'error': 'A club with this name already exists'}), 400

    leader = User.query.filter_by(email=leader_email).first()
    if not leader:
        return jsonify({'error': 'No user found with that email address'}), 404

    existing_leadership = Club.query.filter_by(leader_id=leader.id).first()
    if existing_leadership:
        return jsonify({'error': f'This user is already the leader of {existing_leadership.name}'}), 400

    club = Club(
        name=name,
        description=description,
        location=location,
        leader_id=leader.id,
        balance=balance,
        sync_immune=True  # Admin-created clubs are sync immune by default
    )
    club.generate_join_code()

    db.session.add(club)
    db.session.commit()

    create_audit_log(
        action_type='club_created',
        description=f'Admin {get_current_user().username} created club {club.name}',
        user=get_current_user(),
        target_type='club',
        target_id=club.id,
        category='club'
    )

    return jsonify({
        'success': True,
        'message': f'Club "{name}" created successfully',
        'club': {
            'id': club.id,
            'name': club.name,
            'leader': leader.username,
            'join_code': club.join_code
        }
    })


@admin_bp.route('/projects/review')
@login_required
@reviewer_required
def review_projects():
    """Review pending project submissions from Airtable"""
    current_user = get_current_user()
    return render_template('project_review.html', current_user=current_user)


@admin_bp.route('/projects/<string:project_id>/approve', methods=['POST'])
@login_required
@reviewer_required
def approve_project(project_id):
    """Approve a project submission in Airtable"""
    from app.services.airtable import AirtableService

    airtable_service = AirtableService()

    current_user = get_current_user()

    success = airtable_service.update_ysws_project_submission(project_id, {
        'Status': 'Approved',
        'Decision Reason': f'Approved by {current_user.username}'
    })

    if success:
        # Log project approval
        from app.models.user import create_audit_log
        create_audit_log(
            action_type='project_approved',
            description=f'Admin {current_user.username} approved project {project_id}',
            user=current_user,
            target_type='project',
            target_id=project_id,
            severity='info',
            category='admin',
            admin_action=True
        )
        flash('Project approved!', 'success')
    else:
        flash('Failed to approve project.', 'error')

    return redirect(url_for('admin.review_projects'))


@admin_bp.route('/orders/review')
@login_required
@admin_required
def review_orders():
    """Review pending shop orders from Airtable"""
    airtable_service = AirtableService()
    orders = airtable_service.get_all_orders()

    return render_template('admin_order_review.html', orders=orders)


@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@permission_required('system.manage_settings')
def settings():
    """System settings"""
    system_settings = SystemSettings.query.first()
    if not system_settings:
        system_settings = SystemSettings()
        db.session.add(system_settings)
        db.session.commit()

    if request.method == 'POST':
        system_settings.maintenance_mode = request.form.get('maintenance_mode') == 'on'
        system_settings.economy_enabled = request.form.get('economy_enabled') == 'on'
        system_settings.registration_enabled = request.form.get('registration_enabled') == 'on'

        announcement = sanitize_string(request.form.get('announcement', ''), max_length=500)
        system_settings.announcement = announcement if announcement else None

        db.session.commit()

        flash('Settings updated successfully.', 'success')
        return redirect(url_for('admin.settings'))

    return render_template('admin_settings.html', settings=system_settings)


@admin_bp.route('/stats')
@login_required
@admin_required
def stats():
    """System statistics"""
    airtable_service = AirtableService()
    all_projects = airtable_service.get_ysws_project_submissions()

    stats_data = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_suspended=False).count(),
        'suspended_users': User.query.filter_by(is_suspended=True).count(),
        'total_clubs': Club.query.count(),
        'total_tokens_distributed': db.session.query(
            db.func.sum(ClubTransaction.amount)
        ).filter(ClubTransaction.amount > 0).scalar() or 0,
        'pending_projects': len([p for p in all_projects if p.get('status', '').lower() in ['pending', '']]),
        'approved_projects': len([p for p in all_projects if p.get('status', '').lower() == 'approved']),
    }

    return render_template('admin_stats.html', stats=stats_data)


@admin_bp.route('/pizza-grants')
@login_required
@admin_required
def pizza_grants():
    """Pizza grant management"""
    try:
        airtable_service = AirtableService()
        grants = airtable_service.get_pizza_grants()
    except Exception as e:
        flash(f'Error loading grants: {str(e)}', 'error')
        grants = []

    return render_template('admin_pizza_grants.html', grants=grants)


@admin_bp.route('/activity')
@login_required
@permission_required('admin.view_activity')
def activity():
    """Recent activity log"""
    page = request.args.get('page', 1, type=int)
    per_page = 100

    logs_pagination = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('admin_activity.html',
                         logs=logs_pagination.items,
                         pagination=logs_pagination)


@admin_bp.route('/api/banner-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def api_banner_settings():
    """Get or update banner settings (admin only) - Alias for /api/admin/banner-settings"""
    from app.routes.api import admin_banner_settings
    return admin_banner_settings()


@admin_bp.route('/projects/review/debug')
@login_required
@reviewer_required
def review_projects_debug():
    """Debug page for project review"""
    current_user = get_current_user()
    return render_template('test_projects_debug.html', current_user=current_user)
