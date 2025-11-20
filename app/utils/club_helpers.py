"""
Club helper utilities for the Hack Club Dashboard.
Contains functions for club membership and leadership verification.
"""


def is_user_co_leader(club, user):
    """
    Check if a user is a co-leader of the given club through the membership system.
    """
    if not user or not club:
        return False

    from app.models.club import ClubMembership

    membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user.id, role='co-leader').first()
    return membership is not None


def verify_club_leadership(club, user, require_leader_only=False):
    """
    Verify that a user has leadership privileges for a specific club.
    Returns (is_authorized, role) tuple.
    """
    if not user or not club:
        return False, None

    is_leader = club.leader_id == user.id
    is_co_leader = is_user_co_leader(club, user)

    if require_leader_only:
        return is_leader, 'leader' if is_leader else None
    else:
        is_authorized = is_leader or is_co_leader
        role = 'leader' if is_leader else ('co-leader' if is_co_leader else None)
        return is_authorized, role


