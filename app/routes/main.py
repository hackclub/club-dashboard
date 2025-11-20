"""
Main routes blueprint for the Hack Club Dashboard.
Handles home page, dashboard, gallery, leaderboard, and general pages.
"""

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from app.decorators.auth import login_required
from app.utils.auth_helpers import get_current_user
from app.models.user import User
from app.models.club import Club, ClubMembership
from app.models.gallery import GalleryPost
from app.models.economy import LeaderboardExclusion
from app.models.system import SystemSettings
from extensions import db

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Home page"""
    user = get_current_user()
    if user:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user = get_current_user()

    from app.models.club import ClubMembership
    memberships = ClubMembership.query.filter_by(user_id=user.id).all()
    led_clubs = Club.query.filter_by(leader_id=user.id).all()

    # Don't filter suspended clubs - let them show but redirect on click
    # Admins still see all clubs normally
    
    all_club_ids = set([club.id for club in led_clubs] + [m.club.id for m in memberships])
    if len(all_club_ids) == 1:
        club_id = list(all_club_ids)[0]
        return redirect(url_for('main.club_dashboard', club_id=club_id))

    return render_template('dashboard.html', memberships=memberships, led_clubs=led_clubs)


@main_bp.route('/club-dashboard')
@main_bp.route('/club-dashboard/<int:club_id>')
@login_required
def club_dashboard(club_id=None):
    """Club dashboard"""
    user = get_current_user()

    if club_id:
        club = Club.query.get_or_404(club_id)
    else:
        club = Club.query.filter_by(leader_id=user.id).first()
        if not club:
            from app.models.club import ClubMembership
            membership = ClubMembership.query.filter_by(user_id=user.id).first()
            if membership:
                club = membership.club

        if not club:
            flash('You are not a member of any club', 'error')
            return redirect(url_for('main.dashboard'))

    from app.models.club import ClubMembership
    is_leader = club.leader_id == user.id
    is_co_leader = club.co_leader_id == user.id
    membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user.id).first()
    is_member = membership is not None
    is_admin_access = request.args.get('admin') == 'true' and user.is_admin

    if not is_leader and not is_co_leader and not is_member and not is_admin_access:
        flash('You are not a member of this club', 'error')
        return redirect(url_for('main.dashboard'))

    # Sync suspension status FROM Airtable before checking (bidirectional sync)
    from app.services.airtable import airtable_service
    try:
        airtable_service.sync_club_suspension_from_airtable(club)
    except Exception as e:
        logger.warning(f"Failed to sync suspension status from Airtable: {str(e)}")

    # Redirect to suspension page if club is suspended (unless admin)
    if club.is_suspended and not (user.is_admin or is_admin_access):
        return redirect(url_for('main.club_suspended', club_id=club_id))

    from app.services.airtable import AirtableService
    try:
        airtable_service = AirtableService()
        orders = airtable_service.get_orders_for_club(club.name)
        has_orders = len(orders) > 0
    except:
        has_orders = False

    airtable_data = club.get_airtable_data()
    is_connected_to_directory = airtable_data and airtable_data.get('airtable_id')
    
    # Economy is only enabled if connected to directory
    # Sync-immune clubs without connection should have economy disabled
    economy_enabled = is_connected_to_directory

    if not is_connected_to_directory and not club.sync_immune and not user.is_admin:
        return render_template('club_connection_required.html', club=club, current_user=user)

    banner_settings = {
        'enabled': SystemSettings.get_setting('banner_enabled', 'false') == 'true',
        'title': SystemSettings.get_setting('banner_title', 'Design Contest'),
        'subtitle': SystemSettings.get_setting('banner_subtitle', 'Submit your creative projects!'),
        'icon': SystemSettings.get_setting('banner_icon', 'fas fa-palette'),
        'primary_color': SystemSettings.get_setting('banner_primary_color', '#ec3750'),
        'secondary_color': SystemSettings.get_setting('banner_secondary_color', '#d63146'),
        'background_color': SystemSettings.get_setting('banner_background_color', '#ffffff'),
        'text_color': SystemSettings.get_setting('banner_text_color', '#1a202c'),
        'link_url': SystemSettings.get_setting('banner_link_url', '/gallery'),
        'link_text': SystemSettings.get_setting('banner_link_text', 'Submit Entry')
    }

    membership_date = membership.joined_at if membership else None

    effective_is_leader = is_leader or is_admin_access
    effective_is_co_leader = is_co_leader or is_admin_access
    effective_can_manage = is_leader or is_co_leader or is_admin_access

    return render_template('club_dashboard.html',
                         club=club,
                         membership_date=membership_date,
                         has_orders=has_orders,
                         is_leader=is_leader,
                         is_co_leader=is_co_leader,
                         is_admin_access=is_admin_access,
                         effective_is_leader=effective_is_leader,
                         effective_is_co_leader=effective_is_co_leader,
                         effective_can_manage=effective_can_manage,
                         banner_settings=banner_settings,
                         is_connected_to_directory=is_connected_to_directory,
                         economy_enabled=economy_enabled)


@main_bp.route('/gallery')
def gallery():
    """Public gallery of club posts"""
    posts = GalleryPost.query.order_by(
        GalleryPost.featured.desc(),
        GalleryPost.created_at.desc()
    ).limit(50).all()

    return render_template('gallery.html', posts=posts)


@main_bp.route('/leaderboard')
@main_bp.route('/leaderboard/<leaderboard_type>')
def leaderboard(leaderboard_type='total_tokens'):
    """Club leaderboard"""
    from app.models.club import ClubMembership

    excluded_club_ids = [
        exc.club_id for exc in LeaderboardExclusion.query.filter_by(
            leaderboard_type=leaderboard_type
        ).all()
    ]

    if leaderboard_type == 'total_tokens' or leaderboard_type == 'total':
        clubs = Club.query.filter(
            ~Club.id.in_(excluded_club_ids) if excluded_club_ids else True
        ).order_by(Club.tokens.desc()).limit(100).all()
        title = "Top Clubs by Total Tokens"
    elif leaderboard_type == 'monthly_tokens':
        clubs = Club.query.filter(
            ~Club.id.in_(excluded_club_ids) if excluded_club_ids else True
        ).order_by(Club.tokens.desc()).limit(100).all()
        title = "Top Clubs by Monthly Tokens"
    elif leaderboard_type == 'most_members':
        clubs = Club.query.filter(
            ~Club.id.in_(excluded_club_ids) if excluded_club_ids else True
        ).all()

        for club in clubs:
            club.member_count = ClubMembership.query.filter_by(club_id=club.id).count()
            club.total_members = club.member_count

        clubs = sorted(clubs, key=lambda c: c.member_count, reverse=True)[:100]
        title = "Top Clubs by Member Count"
    else:
        clubs = []
        title = "Leaderboard"

    for i, club in enumerate(clubs, 1):
        club.rank = i
        if not hasattr(club, 'member_count'):
            club.member_count = ClubMembership.query.filter_by(club_id=club.id).count()
        if not hasattr(club, 'total_tokens'):
            club.total_tokens = club.tokens

    return render_template('leaderboard.html',
                         clubs=clubs,
                         title=title,
                         leaderboard_type=leaderboard_type)


@main_bp.route('/join-club')
@login_required
def join_club_redirect():
    """Join a club using a join code"""
    user = get_current_user()
    join_code = request.args.get('code', '').strip().upper()

    if not join_code:
        flash('No join code provided', 'error')
        return redirect(url_for('main.dashboard'))

    club = Club.query.filter_by(join_code=join_code).first()

    if not club:
        flash('Invalid join code', 'error')
        return redirect(url_for('main.dashboard'))

    # Check if club is suspended
    if club.is_suspended:
        flash('This club has been suspended and is not accepting new members', 'error')
        return redirect(url_for('main.dashboard'))

    existing_membership = ClubMembership.query.filter_by(
        club_id=club.id,
        user_id=user.id
    ).first()

    if existing_membership:
        flash(f'You are already a member of {club.name}', 'info')
        return redirect(url_for('main.club_dashboard', club_id=club.id))

    if club.leader_id == user.id or club.co_leader_id == user.id:
        flash(f'You are already a leader of {club.name}', 'info')
        return redirect(url_for('main.club_dashboard', club_id=club.id))

    membership = ClubMembership(
        club_id=club.id,
        user_id=user.id,
        role='member'
    )
    db.session.add(membership)
    db.session.commit()

    flash(f'Successfully joined {club.name}!', 'success')
    return redirect(url_for('main.club_dashboard', club_id=club.id))


@main_bp.route('/maintenance')
def maintenance():
    """Maintenance mode page"""
    return render_template('maintenance.html'), 503


@main_bp.route('/club-suspended/<int:club_id>')
@login_required
def club_suspended(club_id):
    """Club suspension page"""
    club = Club.query.get_or_404(club_id)
    user = get_current_user()
    
    # Verify user is actually a member/leader
    from app.models.club import ClubMembership
    is_leader = club.leader_id == user.id
    is_co_leader = club.co_leader_id == user.id
    membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user.id).first()
    is_member = membership is not None
    
    if not is_leader and not is_co_leader and not is_member and not user.is_admin:
        flash('You are not a member of this club', 'error')
        return redirect(url_for('main.dashboard'))
    
    # If admin or club is not suspended, redirect to normal dashboard
    if not club.is_suspended or user.is_admin:
        return redirect(url_for('main.club_dashboard', club_id=club_id))
    
    return render_template('club_suspended.html', club=club)


@main_bp.route('/suspended')
def suspended():
    """Account suspended page"""
    return render_template('suspended.html'), 403


@main_bp.route('/account')
@login_required
def account():
    """User account settings"""
    user = get_current_user()

    user_roles = [role.name for role in user.roles]
    user_permissions = user.get_all_permissions()

    from app.models.user import Permission
    all_permissions = Permission.query.order_by(Permission.category, Permission.name).all()

    permissions_by_category = {}
    for perm in all_permissions:
        if perm.category not in permissions_by_category:
            permissions_by_category[perm.category] = []
        permissions_by_category[perm.category].append({
            'name': perm.name,
            'description': perm.description,
            'has_permission': perm.name in user_permissions
        })

    show_permissions = len(user_roles) > 0 and not (len(user_roles) == 1 and 'user' in user_roles)

    return render_template('account.html',
                         user=user,
                         user_roles=user_roles,
                         permissions_by_category=permissions_by_category,
                         show_permissions=show_permissions)


@main_bp.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')


@main_bp.route('/help')
def help():
    """Help and FAQ page"""
    return render_template('help.html')


@main_bp.route('/privacy')
def privacy():
    """Privacy policy page"""
    return render_template('privacy.html')


@main_bp.route('/terms')
def terms():
    """Terms of service page"""
    return render_template('terms.html')


@main_bp.route('/raccoon-mascot')
def raccoon_mascot():
    """Easter egg raccoon mascot page"""
    return render_template('raccoon_mascot.html')


@main_bp.route('/pizza-order')
@login_required
def pizza_order():
    """Pizza ordering page"""
    user = get_current_user()
    from app.models.club import ClubMembership
    memberships = ClubMembership.query.filter_by(user_id=user.id).all()
    led_clubs = Club.query.filter_by(leader_id=user.id).all()

    return render_template('pizza_order.html',
                         memberships=memberships,
                         led_clubs=led_clubs)


@main_bp.route('/project-review')
@login_required
def project_review():
    """Project review page (non-admin)"""
    user = get_current_user()

    from app.models.economy import ProjectSubmission
    projects = ProjectSubmission.query.filter_by(user_id=user.id).order_by(
        ProjectSubmission.submitted_at.desc()
    ).all()

    return render_template('project_review.html', projects=projects)
