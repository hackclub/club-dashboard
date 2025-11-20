"""
User and RBAC models for the application.
Includes User, Role, Permission, RolePermission, UserRole, and AuditLog models.
"""
import json
from datetime import datetime, timezone
from flask import request
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


def get_real_ip():
    """Get the real client IP address, accounting for proxies and load balancers"""
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    elif request.headers.get('X-Forwarded-For'):
        forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
        return forwarded_ips[0].strip()
    elif request.headers.get('X-Forwarded-Proto'):
        return request.headers.get('X-Client-IP', request.remote_addr)
    else:
        return request.remote_addr


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    birthday = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    hackatime_api_key = db.Column(db.String(255))
    slack_user_id = db.Column(db.String(255), unique=True)
    identity_token = db.Column(db.String(500))
    identity_verified = db.Column(db.Boolean, default=False, nullable=False)

    registration_ip = db.Column(db.String(45))  # IPv6 addresses can be up to 45 chars
    last_login_ip = db.Column(db.String(45))
    all_ips = db.Column(db.Text)  # JSON array of all IPs used by this user

    totp_secret = db.Column(db.String(32))  # Base32 encoded secret
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    totp_backup_codes = db.Column(db.Text)  # JSON array of hashed backup codes
    totp_enabled_at = db.Column(db.DateTime)

    roles = db.relationship('Role', secondary='user_role',
                           primaryjoin='User.id==UserRole.user_id',
                           secondaryjoin='Role.id==UserRole.role_id',
                           backref='users', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_root_user(self):
        """Check if user is the root user (ethan@hackclub.com) - cannot be demoted"""
        return self.email == 'ethan@hackclub.com'

    def has_role(self, role_name):
        """Check if user has a specific role"""
        return self.roles.filter_by(name=role_name).first() is not None

    def has_permission(self, permission_name):
        """Check if user has a specific permission through any of their roles"""
        if self.is_root_user():
            return True

        for role in self.roles:
            if role.has_permission(permission_name):
                return True
        return False

    def get_all_permissions(self):
        """Get all permissions from all user's roles"""
        permissions = set()
        for role in self.roles:
            for permission in role.permissions:
                permissions.add(permission.name)
        return list(permissions)

    def assign_role(self, role, assigned_by_user=None):
        """Assign a role to this user"""
        if not self.has_role(role.name):
            user_role = UserRole(user_id=self.id, role_id=role.id)
            if assigned_by_user:
                user_role.assigned_by = assigned_by_user.id
            db.session.add(user_role)
            return True
        return False

    def remove_role(self, role_name):
        """Remove a role from this user"""
        if self.is_root_user() and role_name == 'super-admin':
            return False

        user_role = UserRole.query.filter_by(
            user_id=self.id,
            role_id=Role.query.filter_by(name=role_name).first().id
        ).first()
        if user_role:
            db.session.delete(user_role)
            return True
        return False

    @property
    def is_admin(self):
        """Backward compatibility property - checks if user has admin permissions"""
        return (self.is_root_user() or
                self.has_role('super-admin') or
                self.has_role('admin') or
                self.has_role('users-admin'))

    @property
    def is_reviewer(self):
        """Backward compatibility property - checks if user has reviewer permissions"""
        return (self.has_role('reviewer') or
                self.has_permission('reviews.submit') or
                self.is_admin)

    def requires_2fa(self):
        """Check if user has any role that requires 2FA"""
        for role in self.roles:
            if role.requires_2fa:
                return True
        return False

    def get_2fa_required_roles(self):
        """Get list of role names that require 2FA"""
        return [role.display_name for role in self.roles if role.requires_2fa]

    def get_all_ips(self):
        """Get all IPs used by this user as a list"""
        try:
            return json.loads(self.all_ips) if self.all_ips else []
        except:
            return []

    def add_ip(self, ip_address):
        """Add an IP address to the user's IP history"""
        if not ip_address:
            return

        current_ips = self.get_all_ips()

        if ip_address not in current_ips:
            current_ips.append(ip_address)
            if len(current_ips) > 50:
                current_ips = current_ips[-50:]
            self.all_ips = json.dumps(current_ips)

        self.last_login_ip = ip_address

    def generate_totp_secret(self):
        """Generate a new TOTP secret for 2FA"""
        import pyotp
        return pyotp.random_base32()

    def get_totp_uri(self, issuer_name='Hack Club Dashboard'):
        """Get the provisioning URI for TOTP (for QR code)"""
        import pyotp
        if not self.totp_secret:
            return None
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name=issuer_name
        )

    def verify_totp(self, token):
        """Verify a TOTP token"""
        import pyotp
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)

    def generate_backup_codes(self, count=10):
        """Generate backup codes for 2FA"""
        import secrets
        codes = []
        for _ in range(count):
            code = '-'.join([
                ''.join(secrets.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(4))
                for _ in range(2)
            ])
            codes.append(code)
        return codes

    def set_backup_codes(self, codes):
        """Hash and store backup codes"""
        hashed_codes = [generate_password_hash(code) for code in codes]
        self.totp_backup_codes = json.dumps(hashed_codes)

    def get_backup_codes_count(self):
        """Get the count of remaining backup codes"""
        if not self.totp_backup_codes:
            return 0
        try:
            codes = json.loads(self.totp_backup_codes)
            return len(codes)
        except:
            return 0

    def verify_backup_code(self, code):
        """Verify and consume a backup code"""
        if not self.totp_backup_codes:
            return False
        try:
            codes = json.loads(self.totp_backup_codes)
            for i, hashed_code in enumerate(codes):
                if check_password_hash(hashed_code, code):
                    codes.pop(i)
                    self.totp_backup_codes = json.dumps(codes)
                    return True
            return False
        except:
            return False


class Role(db.Model):
    """Roles that can be assigned to users"""
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_system_role = db.Column(db.Boolean, default=False, nullable=False)  # System roles can't be deleted
    requires_2fa = db.Column(db.Boolean, default=False, nullable=False)  # Require 2FA for users with this role
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    permissions = db.relationship('Permission', secondary='role_permission', backref='roles', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'is_system_role': self.is_system_role,
            'requires_2fa': self.requires_2fa,
            'permissions': [p.name for p in self.permissions]
        }

    def has_permission(self, permission_name):
        """Check if role has a specific permission"""
        return self.permissions.filter_by(name=permission_name).first() is not None


class Permission(db.Model):
    """Individual permissions that can be granted to roles"""
    __tablename__ = 'permission'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), nullable=False, index=True)  # users, clubs, content, system, etc.
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'category': self.category
        }


class RolePermission(db.Model):
    """Many-to-many relationship between roles and permissions"""
    __tablename__ = 'role_permission'

    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False, index=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), nullable=False, index=True)
    granted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('role_id', 'permission_id', name='uq_role_permission'),
    )


class UserRole(db.Model):
    """Many-to-many relationship between users and roles"""
    __tablename__ = 'user_role'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False, index=True)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'role_id', name='uq_user_role'),
    )

    assigner = db.relationship('User', foreign_keys=[assigned_by])


class AuditLog(db.Model):
    """Comprehensive audit log for all system activities"""
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)  # Nullable for system actions
    action_type = db.Column(db.String(50), nullable=False, index=True)  # signup, login, create_post, suspend_user, etc.
    action_category = db.Column(db.String(30), nullable=False, index=True)  # auth, user, club, admin, security
    target_type = db.Column(db.String(30), nullable=True)  # user, club, post, etc.
    target_id = db.Column(db.Integer, nullable=True)  # ID of the target object
    description = db.Column(db.Text, nullable=False)  # Human readable description
    details = db.Column(db.Text)  # JSON string with additional details
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='info')  # info, warning, error, critical
    admin_action = db.Column(db.Boolean, default=False, index=True)  # Mark admin actions

    user = db.relationship('User', backref=db.backref('audit_logs', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'System',
            'action_type': self.action_type,
            'action_category': self.action_category,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'description': self.description,
            'details': json.loads(self.details) if self.details else {},
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'severity': self.severity,
            'admin_action': self.admin_action
        }


def create_audit_log(action_type, description, user=None, target_type=None, target_id=None,
                    details=None, severity='info', admin_action=False, category=None):
    """Create an audit log entry"""
    from flask import current_app as app

    try:
        if not category:
            if action_type in ['signup', 'login', 'logout', 'password_change']:
                category = 'auth'
            elif action_type in ['user_suspend', 'user_unsuspend', 'user_promote', 'user_demote']:
                category = 'user'
            elif action_type in ['club_create', 'club_update', 'club_delete', 'member_add', 'member_remove']:
                category = 'club'
            elif action_type in ['project_review', 'project_submission', 'project_grant_override', 'project_delete']:
                category = 'project'
            elif action_type in ['admin_login', 'admin_action', 'system_config']:
                category = 'admin'
            elif action_type in ['security_violation', 'exploit_attempt', 'profanity_violation']:
                category = 'security'
            else:
                category = 'other'

        log_entry = AuditLog(
            user_id=user.id if user else None,
            action_type=action_type,
            action_category=category,
            target_type=target_type,
            target_id=target_id,
            description=description,
            details=json.dumps(details) if details else None,
            ip_address=get_real_ip() if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            severity=severity,
            admin_action=admin_action
        )

        db.session.add(log_entry)
        db.session.commit()

        return log_entry
    except Exception as e:
        app.logger.error(f"Failed to create audit log: {str(e)}")
        try:
            db.session.rollback()
        except:
            pass
        return None


def initialize_rbac_system():
    """Initialize the RBAC system with predefined roles and permissions"""

    permissions_data = [
        ('system.manage_roles', 'Manage Roles', 'Create, edit, and delete roles', 'system'),
        ('system.manage_permissions', 'Manage Permissions', 'Assign permissions to roles', 'system'),
        ('system.view_audit_logs', 'View Audit Logs', 'View system audit logs', 'system'),
        ('system.manage_settings', 'Manage System Settings', 'Modify system configuration', 'system'),

        ('users.view', 'View Users', 'View user list and profiles', 'users'),
        ('users.create', 'Create Users', 'Create new user accounts', 'users'),
        ('users.edit', 'Edit Users', 'Modify user information', 'users'),
        ('users.delete', 'Delete Users', 'Delete user accounts', 'users'),
        ('users.suspend', 'Suspend Users', 'Suspend and unsuspend users', 'users'),
        ('users.assign_roles', 'Assign Roles', 'Assign roles to users', 'users'),
        ('users.impersonate', 'Impersonate Users', 'Login as another user', 'users'),

        ('clubs.view', 'View Clubs', 'View club list and details', 'clubs'),
        ('clubs.create', 'Create Clubs', 'Create new clubs', 'clubs'),
        ('clubs.edit', 'Edit Clubs', 'Modify club information', 'clubs'),
        ('clubs.delete', 'Delete Clubs', 'Delete clubs', 'clubs'),
        ('clubs.suspend', 'Suspend Clubs', 'Suspend and unsuspend clubs', 'clubs'),
        ('clubs.manage_members', 'Manage Club Members', 'Add/remove club members', 'clubs'),
        ('clubs.transfer_leadership', 'Transfer Club Leadership', 'Transfer club ownership', 'clubs'),
        ('clubs.view_team_notes', 'View Team Notes', 'View internal team notes for clubs', 'clubs'),
        ('clubs.edit_team_notes', 'Edit Team Notes', 'Edit internal team notes for clubs', 'clubs'),

        ('content.view', 'View Content', 'View posts and projects', 'content'),
        ('content.create', 'Create Content', 'Create posts and projects', 'content'),
        ('content.edit', 'Edit Content', 'Edit posts and projects', 'content'),
        ('content.delete', 'Delete Content', 'Delete posts and projects', 'content'),
        ('content.moderate', 'Moderate Content', 'Flag and remove inappropriate content', 'content'),

        ('reviews.view', 'View Reviews', 'View project reviews', 'reviews'),
        ('reviews.submit', 'Submit Reviews', 'Review and approve projects', 'reviews'),
        ('reviews.override', 'Override Reviews', 'Override review decisions', 'reviews'),

        ('orders.view', 'View Orders', 'View order submissions in review', 'orders'),
        ('orders.approve', 'Approve Orders', 'Review and approve order status changes', 'orders'),

        ('admin.access_dashboard', 'Access Admin Dashboard', 'Access the admin dashboard', 'admin'),
        ('admin.view_stats', 'View Statistics', 'View system statistics and overview', 'admin'),
        ('admin.view_activity', 'View Activity Logs', 'View activity feed and system logs', 'admin'),
        ('admin.manage_api_keys', 'Manage API Keys', 'Create and manage API keys', 'admin'),
        ('admin.manage_oauth_apps', 'Manage OAuth Apps', 'Create and manage OAuth applications', 'admin'),
        ('admin.export_data', 'Export Data', 'Export users, clubs, and other data', 'admin'),
        ('admin.view_ip_groups', 'View IP Groups', 'View users grouped by IP address', 'admin'),
        ('admin.reset_passwords', 'Reset User Passwords', 'Reset passwords for any user', 'admin'),
        ('admin.login_as_user', 'Login As User', 'Impersonate other users (same as users.impersonate)', 'admin'),
    ]

    permission_objects = {}
    for perm_name, display_name, description, category in permissions_data:
        perm = Permission.query.filter_by(name=perm_name).first()
        if not perm:
            perm = Permission(
                name=perm_name,
                display_name=display_name,
                description=description,
                category=category
            )
            db.session.add(perm)
        permission_objects[perm_name] = perm

    db.session.flush()

    roles_data = {
        'super-admin': {
            'display_name': 'Super Administrator',
            'description': 'Full system access with all permissions',
            'is_system_role': False,  # Changed to allow editing
            'permissions': [perm for perm in permission_objects.keys()]  # All permissions
        },
        'admin': {
            'display_name': 'Administrator',
            'description': 'General administrative access',
            'is_system_role': False,  # Changed to allow editing
            'permissions': [
                'admin.access_dashboard', 'admin.view_stats', 'admin.view_activity',
                'admin.manage_api_keys', 'admin.manage_oauth_apps', 'admin.export_data',
                'admin.view_ip_groups', 'admin.reset_passwords',
                'users.view', 'users.edit', 'users.suspend', 'users.create', 'users.delete',
                'clubs.view', 'clubs.edit', 'clubs.delete', 'clubs.create', 'clubs.suspend', 'clubs.manage_members', 'clubs.transfer_leadership', 'clubs.view_team_notes', 'clubs.edit_team_notes',
                'content.view', 'content.edit', 'content.delete', 'content.moderate', 'content.create',
                'reviews.view', 'reviews.submit', 'reviews.override',
                'orders.view', 'orders.approve',
                'system.view_audit_logs', 'system.manage_settings',
            ]
        },
        'users-admin': {
            'display_name': 'User Administrator',
            'description': 'Manage users and their roles',
            'is_system_role': False,  # Changed to allow editing
            'permissions': [
                'admin.access_dashboard', 'admin.view_stats', 'admin.view_ip_groups',
                'admin.reset_passwords', 'admin.export_data',
                'users.view', 'users.create', 'users.edit', 'users.suspend', 'users.assign_roles', 'users.delete',
                'system.view_audit_logs',
            ]
        },
        'reviewer': {
            'display_name': 'Reviewer',
            'description': 'Review and approve projects',
            'is_system_role': False,  # Changed to allow editing
            'permissions': [
                'admin.access_dashboard', 'admin.view_stats',
                'reviews.view', 'reviews.submit',
                'orders.view',
                'content.view',
                'clubs.view',
                'users.view',
            ]
        },
        'user': {
            'display_name': 'User',
            'description': 'Basic user with standard permissions',
            'is_system_role': False,  # Changed to allow editing
            'permissions': [
                'content.view', 'content.create',
                'clubs.view', 'clubs.create',
            ]
        },
    }

    for role_name, role_data in roles_data.items():
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(
                name=role_name,
                display_name=role_data['display_name'],
                description=role_data['description'],
                is_system_role=role_data['is_system_role']
            )
            db.session.add(role)
            db.session.flush()
        else:
            role.is_system_role = role_data['is_system_role']
            role.display_name = role_data['display_name']
            role.description = role_data['description']

        for perm_name in role_data['permissions']:
            if perm_name in permission_objects:
                perm = permission_objects[perm_name]
                existing = RolePermission.query.filter_by(
                    role_id=role.id,
                    permission_id=perm.id
                ).first()
                if not existing:
                    role_perm = RolePermission(role_id=role.id, permission_id=perm.id)
                    db.session.add(role_perm)

    root_user = User.query.filter_by(email='ethan@hackclub.com').first()
    if root_user:
        super_admin_role = Role.query.filter_by(name='super-admin').first()
        if super_admin_role and not root_user.has_role('super-admin'):
            root_user.assign_role(super_admin_role)

    db.session.commit()
    print("RBAC system initialized successfully!")


def migrate_existing_users_to_rbac():
    """Migrate existing users from old boolean-based permissions to new RBAC system"""
    print("Starting user migration to RBAC system...")

    super_admin_role = Role.query.filter_by(name='super-admin').first()
    admin_role = Role.query.filter_by(name='admin').first()
    reviewer_role = Role.query.filter_by(name='reviewer').first()
    user_role = Role.query.filter_by(name='user').first()

    if not all([super_admin_role, admin_role, reviewer_role, user_role]):
        print("ERROR: Roles not found. Please initialize the RBAC system first.")
        return

    users = User.query.all()
    migrated_count = 0

    for user in users:
        if user.roles.count() > 0:
            continue

        roles_assigned = []

        if user.is_root_user():
            user.assign_role(super_admin_role)
            roles_assigned.append('super-admin')
        elif user.is_admin:
            user.assign_role(admin_role)
            roles_assigned.append('admin')
        elif user.is_reviewer:
            user.assign_role(reviewer_role)
            roles_assigned.append('reviewer')

        if not user.is_suspended:
            user.assign_role(user_role)
            roles_assigned.append('user')

        if roles_assigned:
            migrated_count += 1
            print(f"Migrated user {user.username} ({user.email}) -> Roles: {', '.join(roles_assigned)}")

    db.session.commit()
    print(f"\nMigration complete! {migrated_count} users migrated to RBAC system.")
