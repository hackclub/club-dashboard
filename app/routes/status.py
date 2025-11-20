"""
Status page routes blueprint for the Hack Club Dashboard.
Handles public status page and admin status management.
"""

from flask import Blueprint, render_template, jsonify, request
from datetime import datetime, timezone
from extensions import db
from app.decorators.auth import login_required, admin_required
from app.utils.auth_helpers import get_current_user
from app.utils.sanitization import sanitize_string
from app.models.system import StatusIncident, StatusUpdate

status_bp = Blueprint('status', __name__)


@status_bp.route('/api/status/banner')
def status_banner():
    """API endpoint for status banner (returns active incidents for display)"""
    incidents = StatusIncident.query.filter(
        StatusIncident.status != 'resolved',
        StatusIncident.impact.in_(['major', 'critical'])
    ).order_by(StatusIncident.created_at.desc()).limit(1).all()

    if incidents:
        incident = incidents[0]
        return jsonify({
            'show': True,
            'message': incident.title,
            'severity': incident.impact,
            'status': incident.status,
            'link': '/status'
        })

    return jsonify({'show': False})


@status_bp.route('/status')
def status_page():
    """Public status page"""
    incidents = StatusIncident.query.filter(
        StatusIncident.status != 'resolved'
    ).order_by(StatusIncident.created_at.desc()).limit(10).all()

    resolved_incidents = StatusIncident.query.filter(
        StatusIncident.status == 'resolved'
    ).order_by(StatusIncident.resolved_at.desc()).limit(5).all()

    if any(inc.impact in ['critical', 'major'] for inc in incidents):
        overall_status = 'degraded'
        status_color = 'danger'
    elif any(inc.impact == 'minor' for inc in incidents):
        overall_status = 'minor issues'
        status_color = 'warning'
    else:
        overall_status = 'operational'
        status_color = 'success'

    return render_template('status.html',
                         incidents=incidents,
                         resolved_incidents=resolved_incidents,
                         overall_status=overall_status,
                         status_color=status_color)


@status_bp.route('/api/status', methods=['GET'])
def api_status():
    """API endpoint for status"""
    incidents = StatusIncident.query.filter(
        StatusIncident.status != 'resolved'
    ).order_by(StatusIncident.created_at.desc()).all()

    incidents_data = []
    for incident in incidents:
        updates = StatusUpdate.query.filter_by(
            incident_id=incident.id
        ).order_by(StatusUpdate.created_at.desc()).all()

        incidents_data.append({
            'id': incident.id,
            'title': incident.title,
            'description': incident.description,
            'impact': incident.impact,
            'affected_services': incident.get_affected_services(),
            'created_at': incident.created_at.isoformat() if incident.created_at else None,
            'updates': [{
                'id': update.id,
                'message': update.message,
                'status': update.status,
                'created_at': update.created_at.isoformat() if update.created_at else None
            } for update in updates]
        })

    if any(inc['impact'] in ['critical', 'major'] for inc in incidents_data):
        overall_status = 'degraded'
    elif any(inc['impact'] == 'minor' for inc in incidents_data):
        overall_status = 'minor_issues'
    else:
        overall_status = 'operational'

    return jsonify({
        'status': overall_status,
        'incidents': incidents_data,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


@status_bp.route('/admin/status/incidents', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_incidents():
    """Manage status incidents (admin only)"""
    if request.method == 'GET':
        incidents = StatusIncident.query.order_by(
            StatusIncident.created_at.desc()
        ).limit(50).all()

        incidents_data = []
        for incident in incidents:
            incidents_data.append({
                'id': incident.id,
                'title': incident.title,
                'description': incident.description,
                'status': incident.status,
                'impact': incident.impact,
                'affected_services': incident.get_affected_services(),
                'created_at': incident.created_at.isoformat() if incident.created_at else None,
                'resolved_at': incident.resolved_at.isoformat() if incident.resolved_at else None
            })

        return jsonify({
            'success': True,
            'incidents': incidents_data
        })

    elif request.method == 'POST':
        data = request.get_json()

        title = sanitize_string(data.get('title', ''), max_length=200)
        description = sanitize_string(data.get('description', ''), max_length=2000)
        impact = data.get('impact', 'minor')
        affected_services = data.get('affected_services', [])

        if not title:
            return jsonify({'error': 'Title is required'}), 400

        if impact not in ['minor', 'major', 'critical']:
            return jsonify({'error': 'Invalid impact level'}), 400

        incident = StatusIncident(
            title=title,
            description=description,
            impact=impact,
            created_by=get_current_user().id
        )
        incident.set_affected_services(affected_services)

        db.session.add(incident)
        db.session.commit()

        return jsonify({
            'success': True,
            'incident': {
                'id': incident.id,
                'title': incident.title,
                'impact': incident.impact
            }
        }), 201


@status_bp.route('/admin/status/incidents/<int:incident_id>/updates', methods=['POST'])
@login_required
@admin_required
def add_incident_update(incident_id):
    """Add update to an incident"""
    incident = StatusIncident.query.get_or_404(incident_id)

    data = request.get_json()
    message = sanitize_string(data.get('message', ''), max_length=2000)
    status = data.get('status', 'investigating')

    if not message:
        return jsonify({'error': 'Message is required'}), 400

    update = StatusUpdate(
        incident_id=incident_id,
        message=message,
        status=status,
        created_by=get_current_user().id
    )

    db.session.add(update)
    db.session.commit()

    return jsonify({
        'success': True,
        'update': {
            'id': update.id,
            'message': update.message,
            'status': update.status,
            'created_at': update.created_at.isoformat() if update.created_at else None
        }
    }), 201


@status_bp.route('/admin/status/incidents/<int:incident_id>/resolve', methods=['POST'])
@login_required
@admin_required
def resolve_incident(incident_id):
    """Resolve an incident"""
    incident = StatusIncident.query.get_or_404(incident_id)

    incident.status = 'resolved'
    incident.resolved_at = datetime.now(timezone.utc)

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Incident resolved'
    })
