import os
import json
import requests
import logging
import re
import html
import base64
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, redirect, flash, request, jsonify, url_for, abort, session, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import string
import urllib.parse
from better_profanity import profanity
from dotenv import load_dotenv
import markdown
from markdown.extensions import codehilite
import bleach

# Load environment variables from .env file
load_dotenv()

def markdown_to_html(markdown_content):
    """Convert markdown to safe HTML for club posts"""
    if not markdown_content:
        return ""
    
    # Configure markdown with safe extensions
    md = markdown.Markdown(extensions=['extra', 'codehilite', 'nl2br'], 
                          extension_configs={
                              'codehilite': {
                                  'css_class': 'highlight',
                                  'use_pygments': False
                              }
                          })
    
    # Convert markdown to HTML
    html_content = md.convert(markdown_content)
    
    # Define allowed HTML tags and attributes for club posts
    allowed_tags = [
        'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'a', 'img',
        'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr', 'del', 'ins'
    ]
    
    allowed_attributes = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'code': ['class'],
        'pre': ['class'],
        'th': ['align'],
        'td': ['align']
    }
    
    # Clean HTML with bleach to prevent XSS
    clean_html = bleach.clean(html_content, 
                             tags=allowed_tags, 
                             attributes=allowed_attributes,
                             protocols=['http', 'https', 'mailto'])
    
    return clean_html

try:
    import profanity_check
    PROFANITY_CHECK_AVAILABLE = True
except ImportError:
    PROFANITY_CHECK_AVAILABLE = False

# Security event logging
def log_security_event(event_type, message, user_id=None, ip_address=None):
    """Log security-related events for monitoring"""
    if not ip_address:
        ip_address = get_real_ip() if request else 'unknown'
    
    security_message = f"SECURITY EVENT - {event_type}: {message} | User ID: {user_id} | IP: {ip_address}"
    app.logger.warning(security_message)

# Configure logging for security
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Initialize profanity filters with comprehensive settings
profanity.load_censor_words()  # Load default profanity word list


def get_database_url():
    url = os.getenv('DATABASE_URL')
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    return url

def get_real_ip():
    """Get the real client IP address, accounting for proxies and load balancers"""
    # Check common proxy headers in order of preference
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    elif request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, get the first one (original client)
        forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
        return forwarded_ips[0].strip()
    elif request.headers.get('X-Forwarded-Proto'):
        return request.headers.get('X-Client-IP', request.remote_addr)
    else:
        return request.remote_addr

app = Flask(__name__)

def api_route(rule, **options):
    """Decorator for API routes"""
    def decorator(f):
        return app.route(rule, **options)(f)
    return decorator

# Use environment variable or generate a consistent key
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    # In production, this should be set via environment variable
    # For development/fallback, use a deterministic key based on database URL
    import hashlib
    db_url = get_database_url()
    secret_key = hashlib.sha256(f"hackclub-dashboard-{db_url}".encode()).hexdigest()
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Input validation and sanitization functions
def sanitize_string(value, max_length=None, allow_html=False):
    """Sanitize string input to prevent XSS and injection attacks"""
    if not value:
        return value

    # Convert to string if not already
    value = str(value).strip()

    # Limit length if specified
    if max_length and len(value) > max_length:
        value = value[:max_length]

    # Remove or escape HTML/script tags
    if not allow_html:
        # Remove script tags completely
        value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)
        # Remove other potentially dangerous tags
        value = re.sub(r'<(script|iframe|object|embed|form|input|button|link|style)[^>]*>', '', value, flags=re.IGNORECASE)
        # Escape remaining HTML
        value = html.escape(value)

    # Remove null bytes and other control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value

def sanitize_css_value(value, max_length=None):
    """Sanitize CSS values to prevent CSS injection attacks"""
    if not value:
        return value

    value = str(value).strip()

    # Limit length if specified
    if max_length and len(value) > max_length:
        value = value[:max_length]

    # Remove dangerous CSS patterns that could lead to XSS
    # Remove javascript: URLs
    value = re.sub(r'javascript:', '', value, flags=re.IGNORECASE)
    # Remove data: URLs (except safe image types)
    value = re.sub(r'data:(?!image/(png|jpeg|jpg|gif|webp|svg\+xml))', '', value, flags=re.IGNORECASE)
    # Remove expression() which can execute JavaScript in IE
    value = re.sub(r'expression\s*\(', '', value, flags=re.IGNORECASE)
    # Remove @import which could load external CSS
    value = re.sub(r'@import', '', value, flags=re.IGNORECASE)
    # Remove url() with non-safe protocols
    value = re.sub(r'url\s*\(\s*["\']?(?!https?:)[^)]*["\']?\s*\)', '', value, flags=re.IGNORECASE)
    # Remove semicolons and other characters that could break out of CSS context
    value = re.sub(r'[;"{}]', '', value)
    # Remove control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value

def sanitize_css_color(value):
    """Sanitize CSS color values specifically"""
    if not value:
        return value

    value = str(value).strip()

    # Only allow safe color formats
    # Hex colors (#rgb, #rrggbb, #rrggbbaa)
    hex_pattern = r'^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$'
    # RGB/RGBA colors
    rgb_pattern = r'^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*[01]?\.?\d*)?\s*\)$'
    # HSL/HSLA colors
    hsl_pattern = r'^hsla?\(\s*(\d{1,3})\s*,\s*(\d{1,3})%\s*,\s*(\d{1,3})%\s*(?:,\s*[01]?\.?\d*)?\s*\)$'
    # Named colors (basic set)
    named_colors = ['transparent', 'black', 'white', 'red', 'green', 'blue', 'yellow', 'orange', 'purple', 'pink', 'gray', 'grey', 'brown']

    if re.match(hex_pattern, value):
        return value
    elif re.match(rgb_pattern, value):
        return value
    elif re.match(hsl_pattern, value):
        return value
    elif value.lower() in named_colors:
        return value
    else:
        # Return a safe default if the color format is invalid
        return '#000000'

def sanitize_html_attribute(value, max_length=None):
    """Sanitize values for HTML attributes to prevent attribute injection"""
    if not value:
        return value

    value = str(value).strip()

    # Limit length if specified
    if max_length and len(value) > max_length:
        value = value[:max_length]

    # Remove quotes and other characters that could break out of attribute context
    value = re.sub(r'["\'><=&]', '', value)
    # Remove control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    # Remove potential JavaScript event attributes
    value = re.sub(r'\bon[a-z]+\s*=', '', value, flags=re.IGNORECASE)

    return value

def sanitize_url(value, max_length=None):
    """Sanitize URLs to prevent JavaScript injection and other attacks"""
    if not value:
        return value

    value = str(value).strip()

    # Limit length if specified
    if max_length and len(value) > max_length:
        value = value[:max_length]

    # Only allow safe URL schemes
    allowed_schemes = ['http', 'https', 'mailto', 'tel']

    # Parse URL to check scheme
    try:
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme and parsed.scheme.lower() not in allowed_schemes:
            return '#'  # Return safe default

        # Ensure the URL doesn't contain dangerous patterns
        if 'javascript:' in value.lower() or 'data:' in value.lower() or 'vbscript:' in value.lower():
            return '#'

        return value
    except:
        return '#'  # Return safe default if URL parsing fails

def check_profanity_comprehensive(text):
    """
    Less strict profanity detection to avoid false positives with names.
    Returns True if clear profanity is detected, False otherwise.
    """
    if not text or not isinstance(text, str):
        return False
    
    # Normalize text for better detection
    normalized_text = text.lower().strip()
    
    # Common false positive patterns (names, etc.) to exclude
    false_positive_patterns = [
        r'\b(shi|wang|dong|hung|peng|ling|chen|chan|chang|cheng|jung|sung|young|long|wong|tong|kong|song|pong|ding|ming|jing|king|ping|zing|ring|wing|yang|gang|bang|fang|dang|sang|tang|hang|lang|mang|nang|pang|rang|vang|zang)\b',
        r'\b(kumar|singh|shah|khan|ali|hassan|hussain|ahmad|ahmed)\b',
        r'\b(analytic|analytics|arsenal|assassin|bass|class|glass|mass|pass|brass)\b',
        r'\b(scunthorpe|shitake|shiitake|shitzu|shihtzu)\b'  # Common false positives
    ]
    
    # Check if text matches common false positive patterns
    for pattern in false_positive_patterns:
        if re.search(pattern, normalized_text, re.IGNORECASE):
            return False
    
    # Only use the basic profanity filter, skip aggressive detection methods
    if profanity.contains_profanity(normalized_text):
        # Allow mild words like 'screw', 'crap', 'damn', 'hell' in appropriate contexts
        mild_words = ['screw', 'crap', 'damn', 'hell', 'suck', 'sucks']
        if normalized_text.strip() in mild_words:
            return False
        return True
    
    # Only check spaced out words if they're clearly intentional profanity
    # (require at least 3 spaces to avoid false positives)
    spaced_pattern = re.findall(r'\b\w(?:\s+\w){3,}\b', normalized_text)
    for spaced_word in spaced_pattern:
        no_spaces = re.sub(r'\s+', '', spaced_word)
        if profanity.contains_profanity(no_spaces):
            return True
    
    return False

def filter_profanity_comprehensive(text, replacement="***"):
    """
    Filter profanity with comprehensive evasion detection and replacement.
    Returns the filtered text or raises ValueError if profanity is detected.
    """
    if not text or not isinstance(text, str):
        return text
    
    if check_profanity_comprehensive(text):
        raise ValueError("Content contains inappropriate language")
    
    return text

def validate_username(username):
    """Validate username format"""
    if not username:
        return False, "Username is required"

    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 30:
        return False, "Username must be less than 30 characters"

    # Only allow alphanumeric characters, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"

    return True, username

def validate_email(email):
    """Validate email format"""
    if not email:
        return False, "Email is required"

    email = email.strip().lower()
    if len(email) > 120:
        return False, "Email is too long"

    # Basic email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email format"

    return True, email

def validate_name(name, field_name="Name"):
    """Validate first/last name"""
    if not name:
        return True, ""  # Names are optional

    name = name.strip()
    if len(name) > 50:
        return False, f"{field_name} must be less than 50 characters"

    # Only allow letters, spaces, hyphens, and apostrophes
    if not re.match(r"^[a-zA-Z\s'-]+$", name):
        return False, f"{field_name} can only contain letters, spaces, hyphens, and apostrophes"

    return True, name

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    
    # Check against common weak passwords
    common_passwords = {
        'password', 'password123', '12345678', 'qwertyui', 'qwerty123',
        'admin123', 'welcome123', 'hackclub123', 'password1', '123456789',
        'letmein123', 'password!', 'Welcome123', 'Password123'
    }
    
    if password.lower() in common_passwords:
        return False, "Password is too common. Please choose a more secure password."
    
    # Check for at least one uppercase, lowercase, digit, and special character
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain at least one uppercase letter, lowercase letter, digit, and special character"
    
    return True, password

def suspend_user_for_security_violation(user, violation_type, details=""):
    """Suspend a user for security violations with logging"""
    if not user or user.is_admin:
        return False  # Don't suspend admins
    
    try:
        user.is_suspended = True
        db.session.commit()
        
        # Log the security violation in audit log
        create_audit_log(
            action_type='security_violation',
            description=f"User suspended for {violation_type}",
            user=user,
            target_type='user',
            target_id=user.id,
            details={
                'violation_type': violation_type,
                'details': details,
                'action_taken': 'account_suspended'
            },
            severity='critical',
            category='security'
        )
        
        # Also log the security event (existing system)
        log_security_event(
            violation_type, 
            f"User suspended: {details}",
            user_id=user.id,
            ip_address=get_real_ip()
        )
        
        app.logger.warning(f"SECURITY SUSPENSION - User {user.username} (ID: {user.id}) suspended for {violation_type}: {details}")
        return True
    except Exception as e:
        app.logger.error(f"Error suspending user {user.id}: {str(e)}")
        return False

def detect_exploit_attempts(text, field_context=""):
    """Detect common exploit and penetration testing attempts with context awareness"""
    if not text or not isinstance(text, str):
        return False, ""
    
    text_lower = text.lower().strip()
    
    # More lenient patterns for assignment, meeting, and resource content
    is_content_field = any(keyword in field_context.lower() for keyword in ["assignment", "meeting", "resource", "club_post"])
    
    # SQL Injection patterns
    sql_patterns = [
        r"union\s+select", r"drop\s+table", r"delete\s+from", r"insert\s+into",
        r"alter\s+table", r"create\s+table", r"exec\s*\(",
        r"'.*or.*'", r"'.*and.*'", r"--", r"/\*.*\*/", r"xp_cmdshell",
        r"sp_executesql", r"information_schema", r"sysobjects", r"syscolumns"
    ]
    
    # Only flag "update.*set" if it's not content field
    if not is_content_field:
        sql_patterns.append(r"update\s+.*set")
    
    # XSS patterns
    xss_patterns = [
        r"<script", r"javascript:", r"vbscript:", r"onload=", r"onerror=",
        r"onclick=", r"onmouseover=", r"alert\s*\(", r"document\.cookie",
        r"eval\s*\(", r"fromcharcode", r"<iframe", r"<object", r"<embed"
    ]
    
    # Command injection patterns - more restrictive for content fields
    if is_content_field:
        cmd_patterns = [
            r";\s*rm\s+[^\s]", r";\s*ls\s+[^\s]", r";\s*pwd\s", r";\s*id\s",
            r"&&\s*rm\s+", r"\|\s*rm\s+", r">\s*/dev/null", r"2>&1", r"/etc/passwd",
            r"/bin/sh", r"/bin/bash", r"curl\s+http", r"wget\s+http", r"nc\s+-"
        ]
    else:
        cmd_patterns = [
            r";\s*rm\s+", r";\s*cat\s+", r";\s*ls\s+", r";\s*pwd", r";\s*id",
            r"&&\s*rm\s+", r"\|\s*rm\s+", r">\s*/dev/null", r"2>&1", r"/etc/passwd",
            r"/bin/sh", r"/bin/bash", r"curl\s+", r"wget\s+", r"nc\s+-"
        ]
    
    # Path traversal patterns
    path_patterns = [
        r"\.\.\/", r"\.\.\\", r"..%2f", r"..%5c", r"~root", r"~admin",
        r"/etc/", r"/proc/", r"/sys/", r"c:\\windows", r"c:\\users"
    ]
    
    # LDAP injection patterns
    ldap_patterns = [
        r"\(\|", r"\(&", r"\(!", r"\*\)", r"admin\)", r"user\)", r"password\)"
    ]
    
    # File inclusion patterns - http/https are legitimate protocols, not file inclusion attacks
    file_patterns = [
        r"php://", r"file://", r"ftp://",
        r"include\s*\(", r"require\s*\(", r"include_once", r"require_once"
    ]
    
    all_patterns = {
        "SQL Injection": sql_patterns,
        "XSS": xss_patterns,
        "Command Injection": cmd_patterns,
        "Path Traversal": path_patterns,
        "LDAP Injection": ldap_patterns,
        "File Inclusion": file_patterns
    }
    
    for exploit_type, patterns in all_patterns.items():
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True, exploit_type
    
    return False, ""

def detect_enumeration_attempts(text, field_context=""):
    """Detect reconnaissance and enumeration attempts with context awareness"""
    if not text or not isinstance(text, str):
        return False, ""
    
    text_lower = text.lower().strip()
    
    # Be much more lenient for content fields
    is_content_field = any(keyword in field_context.lower() for keyword in ["assignment", "meeting", "resource", "club_post"])
    
    if is_content_field:
        # Only flag obvious enumeration patterns in content fields
        enum_patterns = [
            r"information_schema", r"sysobjects", r"syscolumns",
            r"web\.config", r"\.htaccess", r"wp-config"
        ]
        
        suspicious_files = [
            r"passwords?\.txt", r"secrets\.txt", r"\.env"
        ]
        
        # Much higher threshold for content fields
        enum_count = sum(1 for pattern in enum_patterns if re.search(pattern, text_lower))
        file_count = sum(1 for pattern in suspicious_files if re.search(pattern, text_lower))
        
        if enum_count >= 2 or file_count >= 2:
            return True, "Enumeration"
    else:
        # Original strict patterns for other content
        enum_patterns = [
            r"admin", r"administrator", r"root", r"test", r"guest", r"user",
            r"backup", r"temp", r"demo", r"default", r"service", r"oracle",
            r"mysql", r"postgres", r"database", r"db", r"config", r"conf"
        ]
        
        suspicious_files = [
            r"web\.config", r"\.htaccess", r"config\.php", r"wp-config",
            r"database\.yml", r"settings\.py", r"\.env", r"secrets",
            r"passwords?\.txt", r"users?\.txt", r"backup", r"dump"
        ]
        
        enum_count = sum(1 for pattern in enum_patterns if re.search(pattern, text_lower))
        file_count = sum(1 for pattern in suspicious_files if re.search(pattern, text_lower))
        
        if enum_count >= 3 or file_count >= 2:
            return True, "Enumeration"
    
    return False, ""

def validate_input_with_security(text, field_name="input", user=None, max_length=None):
    """Comprehensive input validation with auto-suspension for security violations"""
    if not text:
        return True, text
    
    try:
        # Check length before processing to avoid false positives from truncation
        if max_length and len(text) > max_length:
            # For content fields, be more lenient and just return an error instead of suspending
            is_content_field = any(keyword in field_name.lower() for keyword in ["assignment", "meeting", "resource", "club_post"])
            if is_content_field:
                return False, f"Content too long (max {max_length} characters)"
            # For other fields, also just return error to be consistent
            return False, f"Content too long (max {max_length} characters)"
        
        # Basic sanitization without truncation since we've already checked length
        sanitized = sanitize_string(text, max_length=None)
        
        # Check for profanity
        if check_profanity_comprehensive(sanitized):
            # Log the profanity attempt for monitoring but don't suspend
            if user and not user.is_admin:
                app.logger.warning(f"PROFANITY DETECTED - User {user.username} (ID: {user.id}) used inappropriate language in {field_name}: {text[:100]}...")
                create_audit_log(
                    action_type='profanity_violation',
                    description=f"Inappropriate language detected in {field_name}",
                    user=user,
                    target_type='user',
                    target_id=user.id,
                    details={
                        'field_name': field_name,
                        'content_preview': text[:100] + "..." if len(text) > 100 else text
                    },
                    severity='warning',
                    category='security'
                )
            return False, "Please remove inappropriate language from your content and try again."
        
        # Check for exploit attempts with field context
        is_exploit, exploit_type = detect_exploit_attempts(sanitized, field_name)
        if is_exploit and user and not user.is_admin:
            suspend_user_for_security_violation(
                user,
                f"Security Exploit - {exploit_type}",
                f"Detected {exploit_type} attempt in {field_name}: {text[:100]}..."
            )
            return False, "Account suspended for security violation"
        
        # Check for enumeration attempts with field context
        is_enum, enum_type = detect_enumeration_attempts(sanitized, field_name)
        if is_enum and user and not user.is_admin:
            suspend_user_for_security_violation(
                user,
                f"Enumeration Attempt - {enum_type}",
                f"Detected enumeration in {field_name}: {text[:100]}..."
            )
            return False, "Account suspended for suspicious activity"
        
        return True, sanitized
        
    except Exception as e:
        app.logger.error(f"Error in security validation: {str(e)}")
        return False, "Validation error"

# Session configuration for multiple servers with enhanced security
app.config['SESSION_COOKIE_SECURE'] = True if os.getenv('FLASK_ENV') == 'production' else False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Reduced from 30 days
app.config['SESSION_TYPE'] = 'filesystem'


# Security headers
@app.after_request
def add_security_headers(response):
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Strict Transport Security (HTTPS only)
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Content Security Policy - more restrictive
    if not response.headers.get('Content-Security-Policy'):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://server.fillout.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com https://r2cdn.perplexity.ai; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.hackclub.com https://ai.hackclub.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "frame-src 'self' https://forms.hackclub.com https://server.fillout.com; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
    # Permissions Policy (formerly Feature Policy)
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')

HACKCLUB_IDENTITY_URL = os.getenv('HACKCLUB_IDENTITY_URL', 'https://identity.hackclub.com')
HACKCLUB_IDENTITY_CLIENT_ID = os.getenv('HACKCLUB_IDENTITY_CLIENT_ID')
HACKCLUB_IDENTITY_CLIENT_SECRET = os.getenv('HACKCLUB_IDENTITY_CLIENT_SECRET')

# Initialize database
db = SQLAlchemy(app)

# Initialize rate limiter with enhanced security
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per hour", "100 per minute"],  # More restrictive defaults
    storage_uri="memory://",
    strategy="fixed-window",
    headers_enabled=True
)

# Simple User model
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
    hide_email = db.Column(db.Boolean, default=False, nullable=False)
    show_alias = db.Column(db.Boolean, default=False, nullable=False)
    
    # IP address tracking for security
    registration_ip = db.Column(db.String(45))  # IPv6 addresses can be up to 45 chars
    last_login_ip = db.Column(db.String(45))
    all_ips = db.Column(db.Text)  # JSON array of all IPs used by this user

    # RBAC relationships - specify foreign_keys to avoid ambiguity with assigned_by
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
        # Root user has all permissions
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
        # Root user cannot lose super-admin role
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
        
        # Add IP if not already in list
        if ip_address not in current_ips:
            current_ips.append(ip_address)
            # Keep only last 50 IPs to prevent unlimited growth
            if len(current_ips) > 50:
                current_ips = current_ips[-50:]
            self.all_ips = json.dumps(current_ips)
        
        # Update last login IP
        self.last_login_ip = ip_address

# Role-Based Access Control (RBAC) Models
class Role(db.Model):
    """Roles that can be assigned to users"""
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_system_role = db.Column(db.Boolean, default=False, nullable=False)  # System roles can't be deleted
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    permissions = db.relationship('Permission', secondary='role_permission', backref='roles', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'is_system_role': self.is_system_role,
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

    # Relationships
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
    try:
        # Auto-determine category if not provided
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
        # Try to rollback if commit failed
        try:
            db.session.rollback()
        except:
            pass
        return None

def initialize_rbac_system():
    """Initialize the RBAC system with predefined roles and permissions"""

    # Define all permissions
    permissions_data = [
        # System permissions
        ('system.manage_roles', 'Manage Roles', 'Create, edit, and delete roles', 'system'),
        ('system.manage_permissions', 'Manage Permissions', 'Assign permissions to roles', 'system'),
        ('system.view_audit_logs', 'View Audit Logs', 'View system audit logs', 'system'),
        ('system.manage_settings', 'Manage System Settings', 'Modify system configuration', 'system'),

        # User management permissions
        ('users.view', 'View Users', 'View user list and profiles', 'users'),
        ('users.create', 'Create Users', 'Create new user accounts', 'users'),
        ('users.edit', 'Edit Users', 'Modify user information', 'users'),
        ('users.delete', 'Delete Users', 'Delete user accounts', 'users'),
        ('users.suspend', 'Suspend Users', 'Suspend and unsuspend users', 'users'),
        ('users.assign_roles', 'Assign Roles', 'Assign roles to users', 'users'),
        ('users.impersonate', 'Impersonate Users', 'Login as another user', 'users'),

        # Club management permissions
        ('clubs.view', 'View Clubs', 'View club list and details', 'clubs'),
        ('clubs.create', 'Create Clubs', 'Create new clubs', 'clubs'),
        ('clubs.edit', 'Edit Clubs', 'Modify club information', 'clubs'),
        ('clubs.delete', 'Delete Clubs', 'Delete clubs', 'clubs'),
        ('clubs.manage_members', 'Manage Club Members', 'Add/remove club members', 'clubs'),
        ('clubs.transfer_leadership', 'Transfer Club Leadership', 'Transfer club ownership', 'clubs'),

        # Content management permissions
        ('content.view', 'View Content', 'View posts and projects', 'content'),
        ('content.create', 'Create Content', 'Create posts and projects', 'content'),
        ('content.edit', 'Edit Content', 'Edit posts and projects', 'content'),
        ('content.delete', 'Delete Content', 'Delete posts and projects', 'content'),
        ('content.moderate', 'Moderate Content', 'Flag and remove inappropriate content', 'content'),

        # Review permissions
        ('reviews.view', 'View Reviews', 'View project reviews', 'reviews'),
        ('reviews.submit', 'Submit Reviews', 'Review and approve projects', 'reviews'),
        ('reviews.override', 'Override Reviews', 'Override review decisions', 'reviews'),

        # Order review permissions
        ('orders.view', 'View Orders', 'View order submissions in review', 'orders'),
        ('orders.approve', 'Approve Orders', 'Review and approve order status changes', 'orders'),

        # Admin dashboard permissions
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

    # Create permissions
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

    # Define roles with their permissions (all are custom/editable now)
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
                'clubs.view', 'clubs.edit', 'clubs.delete', 'clubs.create', 'clubs.manage_members', 'clubs.transfer_leadership',
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

    # Create roles and assign permissions
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
            # Update existing roles to be editable
            role.is_system_role = role_data['is_system_role']
            role.display_name = role_data['display_name']
            role.description = role_data['description']

        # Assign permissions to role
        for perm_name in role_data['permissions']:
            if perm_name in permission_objects:
                perm = permission_objects[perm_name]
                # Check if role already has this permission
                existing = RolePermission.query.filter_by(
                    role_id=role.id,
                    permission_id=perm.id
                ).first()
                if not existing:
                    role_perm = RolePermission(role_id=role.id, permission_id=perm.id)
                    db.session.add(role_perm)

    # Ensure root user (ethan@hackclub.com) has super-admin role
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

    # Get all roles
    super_admin_role = Role.query.filter_by(name='super-admin').first()
    admin_role = Role.query.filter_by(name='admin').first()
    reviewer_role = Role.query.filter_by(name='reviewer').first()
    user_role = Role.query.filter_by(name='user').first()

    if not all([super_admin_role, admin_role, reviewer_role, user_role]):
        print("ERROR: Roles not found. Please initialize the RBAC system first.")
        return

    # Get all users
    users = User.query.all()
    migrated_count = 0

    for user in users:
        # Skip if user already has roles
        if user.roles.count() > 0:
            continue

        # Assign roles based on old boolean flags
        roles_assigned = []

        # Root user always gets super-admin
        if user.is_root_user():
            user.assign_role(super_admin_role)
            roles_assigned.append('super-admin')
        elif user.is_admin:
            user.assign_role(admin_role)
            roles_assigned.append('admin')
        elif user.is_reviewer:
            user.assign_role(reviewer_role)
            roles_assigned.append('reviewer')

        # All users get the basic user role
        if not user.is_suspended:
            user.assign_role(user_role)
            roles_assigned.append('user')

        if roles_assigned:
            migrated_count += 1
            print(f"Migrated user {user.username} ({user.email}) -> Roles: {', '.join(roles_assigned)}")

    db.session.commit()
    print(f"\nMigration complete! {migrated_count} users migrated to RBAC system.")

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    rate_limit = db.Column(db.Integer, default=1000)  # requests per hour
    scopes = db.Column(db.Text)  # JSON array of allowed scopes

    user = db.relationship('User', backref=db.backref('api_keys', cascade='all, delete-orphan'))

    def generate_key(self):
        self.key = secrets.token_urlsafe(48)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthApplication(db.Model):
    __tablename__ = 'o_auth_application'
    
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    client_secret = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    redirect_uris = db.Column(db.Text)  # JSON array of allowed redirect URIs
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)
    scopes = db.Column(db.Text)  # JSON array of allowed scopes
    
    # Relationships
    tokens = db.relationship(
        'OAuthToken',
        primaryjoin='OAuthApplication.id == OAuthToken.application_id',
        back_populates='application',
        cascade='all, delete-orphan'
    )
    authorization_codes = db.relationship(
        'OAuthAuthorizationCode',
        primaryjoin='OAuthApplication.id == OAuthAuthorizationCode.application_id',
        back_populates='application',
        cascade='all, delete-orphan'
    )

    user = db.relationship('User', backref=db.backref('oauth_applications', cascade='all, delete-orphan'))

    def generate_credentials(self):
        self.client_id = secrets.token_urlsafe(32)
        self.client_secret = secrets.token_urlsafe(64)

    def get_redirect_uris(self):
        try:
            return json.loads(self.redirect_uris) if self.redirect_uris else []
        except:
            return []

    def set_redirect_uris(self, uris_list):
        self.redirect_uris = json.dumps(uris_list)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthToken(db.Model):
    __tablename__ = 'o_auth_token'
    
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    refresh_token = db.Column(db.String(128), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
    scopes = db.Column(db.Text)  # JSON array of granted scopes
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)

    user = db.relationship('User', backref=db.backref('oauth_tokens', cascade='all, delete-orphan'))
    application = db.relationship('OAuthApplication', back_populates='tokens', foreign_keys=[application_id])

    def generate_tokens(self):
        self.access_token = secrets.token_urlsafe(48)
        self.refresh_token = secrets.token_urlsafe(48)
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

class OAuthAuthorizationCode(db.Model):
    __tablename__ = 'o_auth_authorization_code'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('o_auth_application.id'), nullable=False)
    redirect_uri = db.Column(db.String(500), nullable=False)
    scopes = db.Column(db.Text)  # JSON array of requested scopes
    state = db.Column(db.String(500))
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('oauth_authorization_codes', cascade='all, delete-orphan'))
    application = db.relationship('OAuthApplication', back_populates='authorization_codes', foreign_keys=[application_id])

    def generate_code(self):
        self.code = secrets.token_urlsafe(32)
        self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    def get_scopes(self):
        try:
            return json.loads(self.scopes) if self.scopes else []
        except:
            return []

    def set_scopes(self, scopes_list):
        self.scopes = json.dumps(scopes_list)

# API authentication decorators
def api_key_required(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({
                    'error': 'Missing Authorization header',
                    'error_code': 'MISSING_AUTH_HEADER',
                    'message': 'The Authorization header is required for API access',
                    'how_to_fix': 'Include the Authorization header in your request: "Authorization: Bearer YOUR_API_KEY"'
                }), 401
            
            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Invalid Authorization header format',
                    'error_code': 'INVALID_AUTH_FORMAT',
                    'message': 'Authorization header must use Bearer token format',
                    'how_to_fix': 'Use the format: "Authorization: Bearer YOUR_API_KEY"',
                    'received': f'Authorization: {auth_header[:50]}...' if len(auth_header) > 50 else f'Authorization: {auth_header}'
                }), 401

            try:
                api_key = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({
                    'error': 'Malformed Authorization header',
                    'error_code': 'MALFORMED_AUTH_HEADER',
                    'message': 'Authorization header is missing the API key',
                    'how_to_fix': 'Ensure your header follows the format: "Authorization: Bearer YOUR_API_KEY"'
                }), 401

            if not api_key or len(api_key) < 10:
                return jsonify({
                    'error': 'Invalid API key format',
                    'error_code': 'INVALID_KEY_FORMAT',
                    'message': 'API key appears to be malformed or too short',
                    'how_to_fix': 'Ensure you are using the complete API key provided by your administrator'
                }), 401

            key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()

            if not key_obj:
                # Check if key exists but is inactive
                inactive_key = APIKey.query.filter_by(key=api_key, is_active=False).first()
                if inactive_key:
                    return jsonify({
                        'error': 'API key is disabled',
                        'error_code': 'KEY_DISABLED',
                        'message': 'This API key has been disabled by an administrator',
                        'how_to_fix': 'Contact your administrator to reactivate the API key or request a new one'
                    }), 401
                else:
                    return jsonify({
                        'error': 'Invalid API key',
                        'error_code': 'INVALID_API_KEY',
                        'message': 'The provided API key does not exist or has been revoked',
                        'how_to_fix': 'Verify your API key is correct, or contact your administrator for a new one'
                    }), 401

            # Check scopes if provided
            if scopes:
                key_scopes = key_obj.get_scopes()
                if not any(scope in key_scopes for scope in scopes):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'error_code': 'INSUFFICIENT_SCOPES',
                        'message': f'API key does not have required scopes: {", ".join(scopes)}',
                        'required_scopes': scopes,
                        'available_scopes': key_scopes,
                        'how_to_fix': 'Contact your administrator to add the required scopes to your API key'
                    }), 403

            # Update last used timestamp
            try:
                key_obj.last_used_at = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Failed to update API key last_used_at: {e}")

            # Add key info to request context
            request.api_key = key_obj
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def oauth_required(scopes=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({
                    'error': 'Missing Authorization header',
                    'error_code': 'MISSING_AUTH_HEADER',
                    'message': 'OAuth access token is required',
                    'how_to_fix': 'Include the Authorization header: "Authorization: Bearer YOUR_ACCESS_TOKEN"'
                }), 401
            
            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'error': 'Invalid Authorization header format',
                    'error_code': 'INVALID_AUTH_FORMAT',
                    'message': 'Authorization header must use Bearer token format for OAuth',
                    'how_to_fix': 'Use the format: "Authorization: Bearer YOUR_ACCESS_TOKEN"',
                    'received': f'Authorization: {auth_header[:50]}...' if len(auth_header) > 50 else f'Authorization: {auth_header}'
                }), 401

            try:
                access_token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({
                    'error': 'Malformed Authorization header',
                    'error_code': 'MALFORMED_AUTH_HEADER',
                    'message': 'Authorization header is missing the access token',
                    'how_to_fix': 'Ensure your header follows the format: "Authorization: Bearer YOUR_ACCESS_TOKEN"'
                }), 401

            if not access_token or len(access_token) < 10:
                return jsonify({
                    'error': 'Invalid access token format',
                    'error_code': 'INVALID_TOKEN_FORMAT',
                    'message': 'Access token appears to be malformed or too short',
                    'how_to_fix': 'Ensure you are using the complete access token from the OAuth flow'
                }), 401

            token_obj = OAuthToken.query.filter_by(
                access_token=access_token, 
                is_active=True
            ).first()

            if not token_obj:
                # Check if token exists but is inactive
                inactive_token = OAuthToken.query.filter_by(access_token=access_token, is_active=False).first()
                if inactive_token:
                    return jsonify({
                        'error': 'Access token revoked',
                        'error_code': 'TOKEN_REVOKED',
                        'message': 'This access token has been revoked',
                        'how_to_fix': 'Obtain a new access token by repeating the OAuth authorization flow'
                    }), 401
                else:
                    return jsonify({
                        'error': 'Invalid OAuth token',
                        'error_code': 'INVALID_ACCESS_TOKEN',
                        'message': 'The provided access token does not exist',
                        'how_to_fix': 'Verify your access token is correct, or obtain a new one through the OAuth flow'
                    }), 401

            # Check if token is expired
            if token_obj.expires_at < datetime.now(timezone.utc):
                return jsonify({
                    'error': 'OAuth token expired',
                    'error_code': 'TOKEN_EXPIRED',
                    'message': f'Access token expired at {token_obj.expires_at.isoformat()}',
                    'expires_at': token_obj.expires_at.isoformat(),
                    'how_to_fix': 'Use your refresh token to obtain a new access token, or repeat the OAuth authorization flow'
                }), 401

            # Check scopes if provided
            if scopes:
                token_scopes = token_obj.get_scopes()
                if not any(scope in token_scopes for scope in scopes):
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'error_code': 'INSUFFICIENT_SCOPES',
                        'message': f'Access token does not have required scopes: {", ".join(scopes)}',
                        'required_scopes': scopes,
                        'available_scopes': token_scopes,
                        'how_to_fix': 'Request authorization with the required scopes during the OAuth flow'
                    }), 403

            # Add token and user info to request context
            request.oauth_token = token_obj
            request.oauth_user = token_obj.user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(255))
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    co_leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    join_code = db.Column(db.String(8), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    balance = db.Column(db.Numeric(10, 2), default=0.00)
    tokens = db.Column(db.Integer, default=0, nullable=False)
    piggy_bank_tokens = db.Column(db.Integer, default=0, nullable=False)
    # Add check constraint to prevent negative balances
    __table_args__ = (
        db.CheckConstraint('tokens >= 0', name='check_tokens_non_negative'),
        db.CheckConstraint('piggy_bank_tokens >= 0', name='check_piggy_bank_tokens_non_negative'),
    )
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    sync_immune = db.Column(db.Boolean, default=False, nullable=False)  # If True, bypasses intrusive connection popup
    background_image_url = db.Column(db.String(500), nullable=True)  # Custom background image URL
    background_blur = db.Column(db.Integer, default=0)  # Blur intensity (0-100)
    airtable_data = db.Column(db.Text)  # JSON field for additional Airtable metadata

    leader = db.relationship('User', foreign_keys=[leader_id], backref='led_clubs')
    co_leader = db.relationship('User', foreign_keys=[co_leader_id], backref='co_led_clubs')
    members = db.relationship('ClubMembership', back_populates='club', cascade='all, delete-orphan')

    def generate_join_code(self):
        self.join_code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def get_airtable_data(self):
        """Get parsed Airtable data"""
        try:
            return json.loads(self.airtable_data) if self.airtable_data else {}
        except:
            return {}

    def set_airtable_data(self, data):
        """Set Airtable data as JSON"""
        self.airtable_data = json.dumps(data)

class ClubMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='club_memberships')
    club = db.relationship('Club', back_populates='members')

class ClubPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Stores markdown content
    content_html = db.Column(db.Text)  # Stores rendered HTML content
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='posts')
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

    club = db.relationship('Club', backref='assignments')

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

    club = db.relationship('Club', backref='meetings')

class ClubResource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='book')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    club = db.relationship('Club', backref='resources')

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

    club = db.relationship('Club', backref='projects')
    user = db.relationship('User', backref='projects')

class GalleryPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    images = db.Column(db.Text)  # JSON array of image URLs
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    featured = db.Column(db.Boolean, default=False)

    club = db.relationship('Club', backref='gallery_posts')
    user = db.relationship('User', backref='gallery_posts')

    def get_images(self):
        """Get parsed images as a list"""
        try:
            return json.loads(self.images) if self.images else []
        except:
            return []

    def set_images(self, images_list):
        """Set images as JSON"""
        self.images = json.dumps(images_list)

# Cosmetics models
class ClubCosmetic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    cosmetic_id = db.Column(db.String(100), nullable=False)  # e.g., 'rainbow_name', 'vip_role'
    cosmetic_type = db.Column(db.String(50), nullable=False)  # 'name_effect', 'role', 'badge', 'effect'
    cosmetic_name = db.Column(db.String(200), nullable=False)
    price_paid = db.Column(db.Float, nullable=False)  # USD amount paid
    purchased_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)  # For time-limited cosmetics
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationships
    club = db.relationship('Club', backref=db.backref('cosmetics', lazy=True))

class MemberCosmetic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    club_cosmetic_id = db.Column(db.Integer, db.ForeignKey('club_cosmetic.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Leader who assigned it
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('member_cosmetics', lazy=True))
    club = db.relationship('Club', backref=db.backref('member_cosmetics', lazy=True))
    club_cosmetic = db.relationship('ClubCosmetic', backref=db.backref('member_assignments', lazy=True))
    assigned_by_user = db.relationship('User', foreign_keys=[assigned_by])

class ClubTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # User who triggered the transaction
    transaction_type = db.Column(db.String(50), nullable=False)  # 'credit', 'debit', 'grant', 'purchase', 'refund', 'manual'
    amount = db.Column(db.Integer, nullable=False)  # Amount in tokens (positive for credits, negative for debits)
    description = db.Column(db.Text, nullable=False)
    balance_after = db.Column(db.Integer, nullable=False)  # Club balance after this transaction
    reference_id = db.Column(db.String(100), nullable=True)  # Reference to related record (project_id, order_id, etc.)
    reference_type = db.Column(db.String(50), nullable=True)  # 'project', 'shop_order', 'admin_action', etc.
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Admin who created the transaction
    
    # Relationships
    club = db.relationship('Club', backref=db.backref('transactions', lazy=True, order_by='ClubTransaction.created_at.desc()'))
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('club_transactions', lazy=True))
    created_by_user = db.relationship('User', foreign_keys=[created_by])
    
    def to_dict(self):
        return {
            'id': self.id,
            'club_id': self.club_id,
            'user_id': self.user_id,
            'transaction_type': self.transaction_type,
            'amount': self.amount,
            'description': self.description,
            'balance_after': self.balance_after,
            'reference_id': self.reference_id,
            'reference_type': self.reference_type,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'user': {
                'id': self.user.id,
                'username': self.user.username,
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'email': self.user.email
            } if self.user else None,
            'created_by_user': {
                'id': self.created_by_user.id,
                'username': self.created_by_user.username,
                'first_name': self.created_by_user.first_name,
                'last_name': self.created_by_user.last_name,
                'email': self.created_by_user.email
            } if self.created_by_user else None
        }

class ClubSlackSettings(db.Model):
    __tablename__ = 'club_slack_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    channel_id = db.Column(db.String(255))
    channel_name = db.Column(db.String(255))
    is_public = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    club = db.relationship('Club', backref=db.backref('slack_settings', uselist=False, cascade='all, delete-orphan'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'club_id': self.club_id,
            'channel_id': self.channel_id,
            'channel_name': self.channel_name,
            'is_public': self.is_public,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ClubChatMessage(db.Model):
    __tablename__ = 'club_chat_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(1000), nullable=True)  # 1000 char limit, nullable for image-only messages
    image_url = db.Column(db.String(500), nullable=True)  # URL to image on CDN
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    club = db.relationship('Club', backref=db.backref('chat_messages', lazy='dynamic', cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('club_chat_messages', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'club_id': self.club_id,
            'user_id': self.user_id,
            'username': self.user.username,
            'message': self.message,
            'image_url': self.image_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'can_delete': True  # Will be set in the route based on user permissions
        }

# Attendance Management Models
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
    session_type = db.Column(db.String(50), default='meeting')  # meeting, workshop, event, etc.
    max_attendance = db.Column(db.Integer)  # Optional capacity limit
    is_active = db.Column(db.Boolean, default=True)  # Session is open for attendance
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
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
    status = db.Column(db.String(20), default='present')  # present, absent, late, excused
    check_in_time = db.Column(db.DateTime)
    check_out_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)  # Optional notes about attendance
    marked_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Who marked the attendance
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    session = db.relationship('AttendanceSession', back_populates='attendances')
    user = db.relationship('User', foreign_keys=[user_id], backref='attendance_records')
    marker = db.relationship('User', foreign_keys=[marked_by], backref='marked_attendances')
    
    # Unique constraint to prevent duplicate attendance records
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
    organization = db.Column(db.String(100))  # School, company, etc.
    check_in_time = db.Column(db.DateTime)
    check_out_time = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
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

def create_club_transaction(club_id, transaction_type, amount, description, user_id=None, reference_id=None, reference_type=None, created_by=None):
    """Create a new club transaction and update the club balance"""
    try:
        # Use SELECT FOR UPDATE to lock the club record and prevent race conditions
        club = Club.query.filter_by(id=club_id).with_for_update().first()
        if not club:
            return False, "Club not found"
        
        # For debit transactions, check if sufficient balance exists
        if amount < 0 and club.tokens + amount < 0:
            return False, f"Insufficient balance. Current: {club.tokens} tokens, Required: {abs(amount)} tokens"
        
        # Update club balance atomically
        club.tokens += amount
        # Keep balance field in sync (convert tokens to USD)
        club.balance = club.tokens / 100.0
        
        # Create transaction record
        transaction = ClubTransaction(
            club_id=club_id,
            user_id=user_id,
            transaction_type=transaction_type,
            amount=amount,
            description=description,
            balance_after=club.tokens,
            reference_id=reference_id,
            reference_type=reference_type,
            created_by=created_by
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return True, transaction
    except Exception as e:
        db.session.rollback()
        return False, str(e)

def get_current_week_start():
    """Get the start of the current week (Monday)"""
    today = datetime.now().date()
    days_since_monday = today.weekday()
    week_start = today - timedelta(days=days_since_monday)
    return week_start

def update_quest_progress(club_id, quest_type, increment=1):
    """Update quest progress for a club"""
    try:
        week_start = get_current_week_start()
        
        # Find the quest by type
        quest = WeeklyQuest.query.filter_by(quest_type=quest_type, is_active=True).first()
        if not quest:
            return False, "Quest not found"
        
        # Set target based on quest type
        target = 1 if quest_type == 'gallery_post' else 5
        
        # Get or create quest progress record
        progress_record = ClubQuestProgress.query.filter_by(
            club_id=club_id,
            quest_id=quest.id,
            week_start=week_start
        ).first()
        
        if not progress_record:
            progress_record = ClubQuestProgress(
                club_id=club_id,
                quest_id=quest.id,
                week_start=week_start,
                progress=0,
                target=target,
                completed=False,
                reward_claimed=False
            )
            db.session.add(progress_record)
        
        # Update progress
        progress_record.progress += increment
        progress_record.updated_at = datetime.utcnow()
        
        # Check if quest is completed
        if progress_record.progress >= target and not progress_record.completed:
            progress_record.completed = True
            progress_record.completed_at = datetime.utcnow()
            
            # Get club with lock to check piggy bank balance
            club = Club.query.filter_by(id=club_id).with_for_update().first()
            if not club:
                app.logger.error(f"Club {club_id} not found when completing quest")
                return False, "Club not found"
            
            # Check if piggy bank has enough tokens
            if club.piggy_bank_tokens >= quest.reward_tokens:
                # Transfer tokens from piggy bank to regular balance
                club.piggy_bank_tokens -= quest.reward_tokens
                
                # Award tokens to regular balance
                success, transaction = create_club_transaction(
                    club_id=club_id,
                    transaction_type='credit',
                    amount=quest.reward_tokens,
                    description=f'Weekly quest reward: {quest.name} (transferred from piggy bank)',
                    reference_type='weekly_quest',
                    reference_id=str(quest.id),
                    created_by=None
                )
                
                if success:
                    # Create piggy bank debit transaction record
                    try:
                        piggy_success, piggy_transaction = create_club_transaction(
                            club_id=club_id,
                            transaction_type='piggy_bank_debit',
                            amount=-quest.reward_tokens,
                            description=f'Piggy bank deduction for quest reward: {quest.name}',
                            reference_type='weekly_quest',
                            reference_id=str(quest.id),
                            created_by=None
                        )
                        if piggy_success:
                            progress_record.reward_claimed = True
                            app.logger.info(f"Club {club_id} completed quest {quest.name} and received {quest.reward_tokens} tokens from piggy bank (remaining piggy bank: {club.piggy_bank_tokens})")
                        else:
                            app.logger.error(f"Failed to record piggy bank debit transaction: {piggy_transaction}")
                            # Still mark as claimed since the main transaction succeeded
                            progress_record.reward_claimed = True
                    except Exception as piggy_error:
                        app.logger.error(f"Error recording piggy bank transaction: {str(piggy_error)}")
                        # Still mark as claimed since the main transaction succeeded
                        progress_record.reward_claimed = True
                else:
                    # Restore piggy bank tokens if main transaction failed
                    club.piggy_bank_tokens += quest.reward_tokens
                    app.logger.error(f"Failed to award quest tokens: {transaction}")
            else:
                # Not enough tokens in piggy bank - don't award anything
                app.logger.warning(f"Club {club_id} completed quest {quest.name} but piggy bank has insufficient tokens ({club.piggy_bank_tokens} < {quest.reward_tokens}). No reward given.")
                # Still mark as completed but not rewarded
                progress_record.reward_claimed = False
        
        db.session.commit()
        return True, "Quest progress updated"
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating quest progress: {str(e)}")
        return False, str(e)

class LeaderboardExclusion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    leaderboard_type = db.Column(db.String(50), nullable=False)  # 'total_tokens', 'monthly_tokens', etc.
    excluded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    excluded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    reason = db.Column(db.Text)
    
    # Relationships
    club = db.relationship('Club', backref=db.backref('leaderboard_exclusions', lazy=True))
    excluded_by_user = db.relationship('User', backref=db.backref('leaderboard_exclusions', lazy=True))

class ProjectSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('club_project.id'), nullable=True)  # Link to actual project if available
    project_name = db.Column(db.String(200), nullable=False)
    project_url = db.Column(db.String(500))
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('project_submissions', lazy=True))
    club = db.relationship('Club', backref=db.backref('project_submissions', lazy=True))
    project = db.relationship('ClubProject', backref=db.backref('submissions', lazy=True))
    approver = db.relationship('User', foreign_keys=[approved_by], backref=db.backref('approved_submissions', lazy=True))

class WeeklyQuest(db.Model):
    __tablename__ = 'weekly_quests'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    reward_tokens = db.Column(db.Integer, nullable=False)
    quest_type = db.Column(db.String(50), nullable=False)  # gallery_post, member_projects
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ClubQuestProgress(db.Model):
    __tablename__ = 'club_quest_progress'
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    quest_id = db.Column(db.Integer, db.ForeignKey('weekly_quests.id'), nullable=False)
    week_start = db.Column(db.Date, nullable=False)
    progress = db.Column(db.Integer, default=0)
    target = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    reward_claimed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    club = db.relationship('Club', backref=db.backref('quest_progress', lazy=True))
    quest = db.relationship('WeeklyQuest', backref=db.backref('progress_records', lazy=True))
    
    __table_args__ = (db.UniqueConstraint('club_id', 'quest_id', 'week_start', name='_club_quest_week_uc'),)

# Blog Models
class BlogCategory(db.Model):
    __tablename__ = 'blog_category'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    slug = db.Column(db.String(120), nullable=False, unique=True, index=True)
    color = db.Column(db.String(7), default='#3B82F6')  # Hex color code
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<BlogCategory {self.name}>'

class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(250), nullable=False, unique=True, index=True)
    content = db.Column(db.Text, nullable=False)
    summary = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('blog_category.id'), nullable=True)
    
    # Status and visibility
    status = db.Column(db.String(20), default='draft')  # draft, published, archived
    is_featured = db.Column(db.Boolean, default=False)
    published_at = db.Column(db.DateTime, nullable=True)
    
    # Content metadata
    banner_image = db.Column(db.Text)  # URL of banner image
    images = db.Column(db.Text)  # JSON array of image URLs
    tags = db.Column(db.Text)    # JSON array of tags
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    author = db.relationship('User', backref=db.backref('blog_posts', lazy=True))
    category = db.relationship('BlogCategory', backref=db.backref('posts', lazy=True))
    
    def get_images(self):
        """Get images as a list"""
        if self.images:
            return json.loads(self.images)
        return []
    
    def set_images(self, images):
        """Set images from a list"""
        if images:
            self.images = json.dumps(images)
        else:
            self.images = None
    
    def get_tags(self):
        """Get tags as a list"""
        if self.tags:
            return json.loads(self.tags)
        return []
    
    def set_tags(self, tags):
        """Set tags from a list"""
        if tags:
            self.tags = json.dumps(tags)
        else:
            self.tags = None
    
    def __repr__(self):
        return f'<BlogPost {self.title}>'

class SystemSettings(db.Model):
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    updated_by_user = db.relationship('User', backref=db.backref('system_settings_updates', lazy=True))
    
    @staticmethod
    def get_setting(key, default=None):
        """Get a system setting value"""
        try:
            setting = SystemSettings.query.filter_by(key=key).first()
            return setting.value if setting else default
        except Exception as e:
            app.logger.error(f"Error getting setting '{key}': {str(e)}")
            return default
    
    @staticmethod
    def set_setting(key, value, user_id=None):
        """Set a system setting value"""
        try:
            setting = SystemSettings.query.filter_by(key=key).first()
            if setting:
                setting.value = str(value)
                if user_id:
                    # Verify user exists before setting  
                    user_exists = db.session.query(User.query.filter(User.id == user_id).exists()).scalar()
                    if user_exists:
                        setting.updated_by = user_id
            else:
                # Verify user exists before creating setting
                valid_user_id = None
                if user_id:
                    user_exists = db.session.query(User.query.filter(User.id == user_id).exists()).scalar()
                    if user_exists:
                        valid_user_id = user_id
                setting = SystemSettings(key=key, value=str(value), updated_by=valid_user_id)
                db.session.add(setting)
            
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error setting '{key}': {str(e)}")
            return False
    
    @staticmethod
    def get_bool_setting(key, default=False):
        """Get a boolean system setting"""
        value = SystemSettings.get_setting(key, str(default))
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @staticmethod
    def is_maintenance_mode():
        """Check if maintenance mode is enabled"""
        return SystemSettings.get_bool_setting('maintenance_mode', False)
    
    @staticmethod
    def is_economy_enabled():
        """Check if economy is enabled"""
        return SystemSettings.get_bool_setting('economy_enabled', True)
    
    @staticmethod
    def is_admin_economy_override_enabled():
        """Check if admin economy override is enabled"""
        return SystemSettings.get_bool_setting('admin_economy_override', False)
    
    @staticmethod
    def is_club_creation_enabled():
        """Check if club creation is enabled"""
        return SystemSettings.get_bool_setting('club_creation_enabled', True)
    
    @staticmethod
    def is_user_registration_enabled():
        """Check if user registration is enabled"""
        return SystemSettings.get_bool_setting('user_registration_enabled', True)
    
    @staticmethod
    def is_mobile_enabled():
        """Check if mobile dashboard is enabled"""
        return SystemSettings.get_bool_setting('mobile_enabled', True)
    
    @staticmethod
    def is_heidi_enabled():
        """Check if Heidi chatbot is enabled"""
        return SystemSettings.get_bool_setting('heidi_enabled', True)

class StatusIncident(db.Model):
    __tablename__ = 'status_incident'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='investigating')  # investigating, identified, monitoring, resolved
    impact = db.Column(db.String(50), nullable=False, default='minor')  # minor, major, critical
    affected_services = db.Column(db.Text)  # JSON array of affected services
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('created_incidents', lazy=True))
    
    def get_affected_services(self):
        """Get affected services as a list"""
        if self.affected_services:
            try:
                import json
                return json.loads(self.affected_services)
            except:
                return []
        return []
    
    def set_affected_services(self, services_list):
        """Set affected services from a list"""
        import json
        self.affected_services = json.dumps(services_list)
    
    def get_duration(self):
        """Get incident duration in human readable format"""
        if self.resolved_at:
            # Both timestamps should be timezone-aware
            resolved_at = self.resolved_at
            if resolved_at.tzinfo is None:
                resolved_at = resolved_at.replace(tzinfo=timezone.utc)
            created_at = self.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            delta = resolved_at - created_at
        else:
            # Handle timezone-aware vs naive datetime comparison
            created_at = self.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - created_at
        
        total_seconds = int(delta.total_seconds())
        if total_seconds < 0:
            return "0s"  # Handle negative durations
        elif total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            return f"{total_seconds // 60}m"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days}d {hours}h"
    
    def to_dict(self):
        def format_timestamp(dt):
            """Format timestamp ensuring timezone info"""
            if not dt:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'impact': self.impact,
            'affected_services': self.get_affected_services(),
            'created_at': format_timestamp(self.created_at),
            'updated_at': format_timestamp(self.updated_at),
            'resolved_at': format_timestamp(self.resolved_at),
            'duration': self.get_duration(),
            'creator': {
                'id': self.creator.id,
                'username': self.creator.username
            } if self.creator else None
        }

class StatusUpdate(db.Model):
    __tablename__ = 'status_update'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('status_incident.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False)  # investigating, identified, monitoring, resolved
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    incident = db.relationship('StatusIncident', backref=db.backref('updates', lazy=True, order_by='StatusUpdate.created_at'))
    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('status_updates', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'creator': {
                'id': self.creator.id,
                'username': self.creator.username
            } if self.creator else None
        }

def is_user_co_leader(club, user):
    """
    Check if a user is a co-leader of the given club through the membership system.
    """
    if not user or not club:
        return False
    
    membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user.id, role='co-leader').first()
    return membership is not None

# Club authorization helper
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

def club_has_gallery_post(club_id):
    """
    Check if a club has made at least one gallery post.
    Returns True if the club has at least one gallery post, False otherwise.
    NOTE: Gallery post requirement has been disabled - always returns True.
    """
    # Gallery post requirement disabled - always return True to allow shop access
    return True

# Authentication helpers
def get_current_user():
    user_id = session.get('user_id')
    logged_in = session.get('logged_in')

    if not user_id or not logged_in:
        return None

    try:
        user = db.session.get(User, int(user_id))
        if not user:
            # Clear invalid session
            session.clear()
            return None
        return user
    except Exception as e:
        app.logger.error(f"Error getting current user: {e}")
        try:
            db.session.rollback()
            # Create a new session for retry
            db.session.close()
            user = db.session.get(User, int(user_id))
            if not user:
                session.clear()
            return user
        except Exception as e2:
            app.logger.error(f"Error on retry getting current user: {e2}")
            session.clear()
            return None

def login_user(user, remember=False):
    session['user_id'] = user.id
    session['logged_in'] = True
    if remember:
        session.permanent = True
    user.last_login = datetime.now(timezone.utc)
    real_ip = get_real_ip()
    user.add_ip(real_ip)  # Add current IP to user's IP history
    try:
        db.session.commit()
        app.logger.info(f"User login: {user.username} (ID: {user.id}) from IP: {real_ip}")
        
        # Create audit log for login
        create_audit_log(
            action_type='login',
            description=f"User {user.username} logged in",
            user=user,
            details={
                'remember_me': remember,
                'user_agent': request.headers.get('User-Agent') if request else None
            },
            category='auth'
        )
    except:
        db.session.rollback()
        app.logger.error(f"Failed to update last_login for user {user.id}")

def logout_user():
    session.pop('user_id', None)
    session.pop('logged_in', None)
    session.clear()

def is_authenticated():
    return session.get('logged_in') and session.get('user_id')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        authenticated = is_authenticated()
        current_user = get_current_user()

        app.logger.debug(f"Auth check for {request.endpoint}: authenticated={authenticated}, user_id={session.get('user_id')}, logged_in={session.get('logged_in')}, current_user={current_user.username if current_user else None}")

        if not authenticated or not current_user:
            app.logger.warning(f"Authentication failed for {request.endpoint}: user_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        
        # Check if user is suspended (but allow access to suspended page and logout)
        if current_user.is_suspended and request.endpoint not in ['suspended', 'logout']:
            if request.is_json:
                return jsonify({'error': 'Account suspended'}), 403
            return redirect(url_for('suspended'))

        return f(*args, **kwargs)
    return decorated_function

def permission_required(*permissions):
    """Decorator to check if user has specific permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            authenticated = is_authenticated()
            current_user = get_current_user()

            if not authenticated or not current_user:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('login'))

            # Check if user has at least one of the required permissions
            has_permission = False
            for perm in permissions:
                if current_user.has_permission(perm):
                    has_permission = True
                    break

            if not has_permission:
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('You do not have permission to access this resource.', 'error')
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def role_required(*roles):
    """Decorator to check if user has specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            authenticated = is_authenticated()
            current_user = get_current_user()

            if not authenticated or not current_user:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('login'))

            # Check if user has at least one of the required roles
            has_role = False
            for role in roles:
                if current_user.has_role(role):
                    has_role = True
                    break

            if not has_role:
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('You do not have permission to access this resource.', 'error')
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Admin access decorator - checks for RBAC admin permissions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        authenticated = is_authenticated()
        current_user = get_current_user()

        if not authenticated or not current_user:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))

        # Check RBAC permissions
        has_admin_access = (
            current_user.has_permission('admin.access_dashboard') or
            current_user.has_role('super-admin') or
            current_user.has_role('admin') or
            current_user.has_role('users-admin')
        )

        if not has_admin_access:
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            flash('Admin access required', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function

def reviewer_required(f):
    """Reviewer access decorator - checks for RBAC reviewer permissions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        authenticated = is_authenticated()
        current_user = get_current_user()

        if not authenticated or not current_user:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))

        # Check RBAC permissions
        has_reviewer_access = (
            current_user.has_permission('reviews.submit') or
            current_user.has_role('super-admin') or
            current_user.has_role('admin') or
            current_user.has_role('reviewer')
        )

        if not has_reviewer_access:
            if request.is_json:
                return jsonify({'error': 'Reviewer access required'}), 403
            flash('Reviewer access required', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function

# Make current_user available in templates
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user(), get_current_user=get_current_user)

# Airtable Service for Pizza Grants and Club Management
class AirtableService:
    def __init__(self):
        self.api_token = os.environ.get('AIRTABLE_TOKEN')
        self.base_id = os.environ.get('AIRTABLE_BASE_ID', 'appSnnIu0BhjI3E1p')
        self.table_name = os.environ.get('AIRTABLE_TABLE_NAME', 'Grants')
        # New club management base
        self.clubs_base_id = os.environ.get('AIRTABLE_CLUBS_BASE_ID', 'appSUAc40CDu6bDAp')
        self.clubs_table_id = os.environ.get('AIRTABLE_CLUBS_TABLE_ID', 'tbl5saCV1f7ZWjsn0')
        self.clubs_table_name = os.environ.get('AIRTABLE_CLUBS_TABLE_NAME', 'Clubs Dashboard')
        # Email verification table
        self.email_verification_table_name = 'Dashboard Email Verification'
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }
        encoded_table_name = urllib.parse.quote(self.table_name)
        self.base_url = f'https://api.airtable.com/v0/{self.base_id}/{encoded_table_name}'
        
        # Club management URLs - use table ID for direct access
        self.clubs_base_url = f'https://api.airtable.com/v0/{self.clubs_base_id}/{self.clubs_table_id}'
        # Email verification URL
        self.email_verification_url = f'https://api.airtable.com/v0/{self.clubs_base_id}/{urllib.parse.quote(self.email_verification_table_name)}'
    
    def _validate_airtable_url(self, url):
        """Validate that URL is a legitimate Airtable API URL to prevent SSRF"""
        try:
            parsed = urllib.parse.urlparse(url)
            return (parsed.scheme in ['https'] and 
                   parsed.hostname == 'api.airtable.com' and
                   parsed.path.startswith('/v0/'))
        except:
            return False
    
    def _safe_request(self, method, url, **kwargs):
        """Make a safe HTTP request with URL validation and timeout"""
        if not self._validate_airtable_url(url):
            raise ValueError(f"Invalid Airtable URL: {url}")
        
        # Add timeout to prevent hanging requests - longer for email operations
        kwargs.setdefault('timeout', 60)
        
        if method.upper() == 'GET':
            return requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            return requests.post(url, **kwargs)
        elif method.upper() == 'PATCH':
            return requests.patch(url, **kwargs)
        elif method.upper() == 'DELETE':
            return requests.delete(url, **kwargs)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    def _check_school_variations(self, club_name, venue):
        """Check for common school name variations"""
        # Remove common words that might cause mismatches
        common_words = ['high', 'school', 'college', 'university', 'academy', 'the', 'of', 'at']
        
        # Extract main words from both names
        club_words = [word for word in club_name.split() if word not in common_words and len(word) > 2]
        venue_words = [word for word in venue.split() if word not in common_words and len(word) > 2]
        
        # Check if any significant words match
        for club_word in club_words:
            for venue_word in venue_words:
                if (club_word in venue_word or venue_word in club_word or
                    # Check for common abbreviations
                    (club_word.startswith(venue_word[:3]) and len(venue_word) > 3) or
                    (venue_word.startswith(club_word[:3]) and len(club_word) > 3)):
                    return True
        
        return False

    def verify_club_leader(self, email, club_name):
        if not self.api_token:
            app.logger.error("Airtable API token not configured")
            return False
        
        if not self.clubs_base_id or not self.clubs_table_name:
            app.logger.error("Airtable clubs base ID or table name not configured")
            return False
        
        # Validate email format to prevent injection
        if not email or '@' not in email or len(email) < 3:
            app.logger.error("Invalid email format for verification")
            return False
        
        # Escape email for safe use in formula - prevent wildcard matching
        escaped_email = email.replace('"', '""').replace("'", "''")
        
        # Validate email contains proper domain
        if email.count('@') != 1:
            app.logger.error("Invalid email format - multiple @ symbols")
            return False
            
        try:
            # Use exact email matching instead of FIND to prevent wildcard abuse
            email_filter_params = {
                'filterByFormula': f'{{Current Leaders\' Emails}} = "{escaped_email}"'
            }
            
            app.logger.info(f"Verifying club leader: email={email}, club={club_name}")
            app.logger.debug(f"Airtable URL: {self.clubs_base_url}")
            app.logger.debug(f"Email filter formula: {email_filter_params['filterByFormula']}")
            
            # Validate the URL to prevent SSRF
            parsed_url = urllib.parse.urlparse(self.clubs_base_url)
            if parsed_url.hostname not in ['api.airtable.com']:
                app.logger.error(f"Invalid Airtable URL hostname: {parsed_url.hostname}")
                return False
            
            response = self._safe_request('GET', self.clubs_base_url, headers=self.headers, params=email_filter_params)
            
            app.logger.info(f"Airtable response status: {response.status_code}")
            app.logger.debug(f"Airtable response headers: {dict(response.headers)}")
            app.logger.debug(f"Airtable response content length: {len(response.content) if response.content else 0}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    app.logger.debug(f"Airtable response data keys: {list(data.keys()) if data else 'None'}")
                    records = data.get('records', [])
                    app.logger.info(f"Found {len(records)} records with email {email}")
                    if records:
                        app.logger.debug(f"First record fields: {list(records[0].get('fields', {}).keys()) if records else 'None'}")
                except ValueError as json_error:
                    app.logger.error(f"Failed to parse Airtable JSON response: {json_error}")
                    app.logger.error(f"Raw response content: {response.text[:500]}...")
                    return False
                
                if len(records) == 0:
                    app.logger.info("No records found with that email address")
                    return False
                
                # Check if any of the records match the club name (case-insensitive partial match)
                club_name_lower = club_name.lower().strip()
                
                # Log all available club names for debugging
                club_names = [record.get('fields', {}).get('Club Name', '') for record in records]
                app.logger.info(f"Available club names for {email}: {club_names}")
                app.logger.debug(f"Full record data for debugging: {[record.get('fields', {}) for record in records]}")
                
                for record in records:
                    fields = record.get('fields', {})
                    venue = fields.get('Club Name', '').lower().strip()
                    app.logger.debug(f"Checking club name: '{venue}' against requested club name: '{club_name_lower}'")
                    
                    # Try multiple matching strategies with more flexible matching
                    if (club_name_lower in venue or 
                        venue.find(club_name_lower) >= 0 or
                        # Check if club name words are in venue
                        any(word.strip() in venue for word in club_name_lower.split() if len(word.strip()) > 2) or
                        # Check if venue words are in club name
                        any(word.strip() in club_name_lower for word in venue.split() if len(word.strip()) > 2) or
                        # Check for common school/high school variations
                        self._check_school_variations(club_name_lower, venue)):
                        app.logger.info(f"Found matching club: {fields.get('Club Name', '')}")
                        return True
                
                app.logger.info(f"No club name match found for '{club_name}' in available clubs: {club_names}")
                return False
                
            elif response.status_code == 403:
                app.logger.error(f"Airtable 403 Forbidden - check API token permissions. Response: {response.text}")
                return False
            elif response.status_code == 404:
                app.logger.error(f"Airtable 404 Not Found - check base ID and table name. Response: {response.text}")
                return False
            else:
                app.logger.error(f"Airtable API error {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"Exception during Airtable verification: {str(e)}")
            return False

    def log_pizza_grant(self, submission_data):
        if not self.api_token:
            app.logger.error("Airtable API token not configured")
            return None

        try:
            hours = float(submission_data.get('project_hours', 0))
            
            # New detailed earning structure: $5 per hour, capped at $20
            # Must be in-person meeting and have 3+ members to redeem
            grant_amount = min(hours * 5, 20)  # $5/hour, max $20
            
            # Round down to nearest dollar for clean amounts
            grant_amount = int(grant_amount)
            
            # Ensure minimum requirements are met for any grant
            if grant_amount > 0:
                # Check if club meets requirements (will be validated on submission)
                is_in_person = submission_data.get('is_in_person_meeting', False)
                club_member_count = submission_data.get('club_member_count', 0)
                
                if not is_in_person:
                    grant_amount = 0
                    app.logger.info(f"Grant denied: Not an in-person meeting")
                elif club_member_count < 3:
                    grant_amount = 0
                    app.logger.info(f"Grant denied: Club has {club_member_count} members, need 3+")
                else:
                    app.logger.info(f"Grant approved: ${grant_amount} for {hours} hours (in-person meeting, {club_member_count} members)")

            # Use YSWS Project Submission table fields - updated field names to match actual table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'

            fields = {
                'Code URL': submission_data.get('github_url', ''),
                'Playable URL': submission_data.get('live_url', ''),
                'First Name': submission_data.get('first_name', ''),
                'Last Name': submission_data.get('last_name', ''),
                'Email': submission_data.get('email', ''),
                'Age': submission_data.get('age', ''),
                'Status': 'Pending',
                'Decision Reason': '',
                'How did you hear about this?': 'Through Club Leader',
                'What are we doing well?': submission_data.get('doing_well', ''),
                'How can we improve?': submission_data.get('improve', ''),
                'Screenshot': [{'url': submission_data.get('screenshot_url', '')}] if submission_data.get('screenshot_url') else [],
                'Description': submission_data.get('project_description', ''),
                'GitHub Username': submission_data.get('github_username', ''),
                'Address (Line 1)': submission_data.get('address_1', ''),
                'Address (Line 2)': submission_data.get('address_2', ''),
                'City': submission_data.get('city', ''),
                'State / Province': submission_data.get('state', ''),
                'Country': submission_data.get('country', ''),
                'ZIP / Postal Code': submission_data.get('zip', ''),
                'Birthday': submission_data.get('birthday', ''),
                'Hackatime Project': submission_data.get('project_name', ''),
                'Hours': float(hours),
                'Grant Amount': float(grant_amount),
                'Club Name': submission_data.get('club_name', ''),
                'Leader Email': submission_data.get('leader_email', ''),
                'In-Person Meeting': 'Yes' if submission_data.get('is_in_person_meeting', False) else 'No',
                'Club Member Count': str(submission_data.get('club_member_count', 0)),
                'Meeting Requirements Met': 'Yes' if (submission_data.get('is_in_person_meeting', False) and submission_data.get('club_member_count', 0) >= 3) else 'No'
            }

            # Debug log submission data
            app.logger.debug(f"Club name in submission_data: '{submission_data.get('club_name', 'NOT_FOUND')}'")
            app.logger.debug(f"Leader email in submission_data: '{submission_data.get('leader_email', 'NOT_FOUND')}'")
            
            # Remove empty fields to avoid validation issues
            fields_before_filter = fields.copy()
            fields = {k: v for k, v in fields.items() if v not in [None, '', []]}
            
            # Log which fields were filtered out
            filtered_out = set(fields_before_filter.keys()) - set(fields.keys())
            if filtered_out:
                app.logger.debug(f"Fields filtered out due to empty values: {filtered_out}")

            payload = {'records': [{'fields': fields}]}
            
            app.logger.info(f"Submitting to Airtable: {project_url}")
            app.logger.debug(f"Airtable payload fields: {list(fields.keys())}")
            app.logger.info(f"Screenshot field value: {fields.get('Screenshot', 'NOT_FOUND')}")
            app.logger.debug(f"Full payload: {payload}")
            
            response = requests.post(project_url, headers=self.headers, json=payload)
            
            app.logger.info(f"Airtable response status: {response.status_code}")
            if response.status_code not in [200, 201]:
                app.logger.error(f"Airtable submission failed: {response.text}")
                return None
            
            app.logger.info("Successfully submitted to Airtable")
            return response.json()
            
        except Exception as e:
            app.logger.error(f"Exception in log_pizza_grant: {str(e)}")
            return None

    def submit_pizza_grant(self, grant_data):
        """Submit pizza grant to Grants table"""
        if not self.api_token:
            return None

        # Use Grants table instead
        grants_table_name = urllib.parse.quote('Grants')
        grants_url = f'https://api.airtable.com/v0/{self.base_id}/{grants_table_name}'

        fields = {
            'Club': grant_data.get('club_name', ''),
            'Email': grant_data.get('contact_email', ''),
            'Status': 'In progress',
            'Grant Amount': float(grant_data.get('grant_amount', 0)),
            'Grant Type': 'Pizza Card',
            'Address': grant_data.get('club_address', ''),
            'Order ID': grant_data.get('order_id', '')
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(grants_url, headers=self.headers, json=payload)
            app.logger.debug(f"Airtable response status: {response.status_code}")
            app.logger.debug(f"Airtable response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                app.logger.error(f"Airtable error: {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Exception submitting to Airtable: {str(e)}")
            return None

    def submit_purchase_request(self, purchase_data):
        """Submit purchase request to Grant Fulfillment table"""
        if not self.api_token:
            return None

        # Use Grant Fulfillment table
        fulfillment_table_name = urllib.parse.quote('Grant Fulfillment')
        fulfillment_url = f'https://api.airtable.com/v0/{self.base_id}/{fulfillment_table_name}'

        fields = {
            'Leader First Name': purchase_data.get('leader_first_name', ''),
            'Leader Last Name': purchase_data.get('leader_last_name', ''),
            'Leader Email': purchase_data.get('leader_email', ''),
            'Purchase Type': purchase_data.get('purchase_type', ''),
            'Purchase Description': purchase_data.get('description', ''),
            'Purchase Reason': purchase_data.get('reason', ''),
            'Fulfillment Method': purchase_data.get('fulfillment_method', ''),
            'Status': 'Pending',
            'Club Name': purchase_data.get('club_name', ''),
            'Amount': str(purchase_data.get('amount', 0))
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(fulfillment_url, headers=self.headers, json=payload)
            app.logger.debug(f"Airtable Grant Fulfillment response status: {response.status_code}")
            app.logger.debug(f"Airtable Grant Fulfillment response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                app.logger.error(f"Airtable Grant Fulfillment error: {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Exception submitting to Airtable Grant Fulfillment: {str(e)}")
            return None

    def get_pizza_grant_submissions(self):
        if not self.api_token:
            return []

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            
            response = requests.get(project_url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                submissions = []
                for record in records:
                    fields = record.get('fields', {})
                    submissions.append({
                        'id': record['id'],
                        'project_name': fields.get('Hackatime Project', ''),
                        'first_name': fields.get('First Name', ''),
                        'last_name': fields.get('Last Name', ''),
                        'email': fields.get('Email', ''),
                        'club_name': fields.get('Club Name', fields.get('Hack Club', '')),
                        'description': fields.get('Description', ''),
                        'github_url': fields.get('Code URL', ''),
                        'live_url': fields.get('Playable URL', ''),
                        'doing_well': fields.get('What are we doing well?', ''),
                        'improve': fields.get('How can we improve?', ''),
                        'address_1': fields.get('Address (Line 1)', ''),
                        'city': fields.get('City', ''),
                        'state': fields.get('State / Province', ''),
                        'zip': fields.get('ZIP / Postal Code', ''),
                        'country': fields.get('Country', ''),
                        'hours': fields.get('Hours', 0),
                        'grant_amount': fields.get('Grant Amount Override') or fields.get('Grant Amount', ''),
                        'status': fields.get('Status', fields.get('Grant Status', fields.get('Review Status', 'Pending'))),
                        'created_time': record.get('createdTime', '')
                    })

                return submissions
            else:
                app.logger.error(f"Failed to fetch submissions: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            app.logger.error(f"Error fetching pizza grant submissions: {str(e)}")
            return []

    def get_submission_by_id(self, submission_id):
        if not self.api_token:
            return None

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"
            
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                fields = data.get('fields', {})
                return {
                    'id': data['id'],
                    'project_name': fields.get('Hackatime Project', ''),
                    'hours': fields.get('Hours', 0),
                    'status': 'Submitted'
                }
            return None
        except Exception as e:
            app.logger.error(f"Error fetching submission {submission_id}: {str(e)}")
            return None

    def update_submission_status(self, submission_id, action):
        if not self.api_token:
            return False

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"
            
            # Map action to status
            status = 'Approved' if action == 'approve' else 'Rejected'
            
            # First, try to get the current record to see what fields exist
            get_response = requests.get(url, headers=self.headers)
            if get_response.status_code == 200:
                current_record = get_response.json()
                fields = current_record.get('fields', {})
                app.logger.info(f"Current record fields: {list(fields.keys())}")
            
            # Try different status field names one by one
            possible_status_fields = ['Status', 'Grant Status', 'Review Status', 'Approval Status']
            
            for field_name in possible_status_fields:
                update_data = {
                    'fields': {
                        field_name: status
                    }
                }
                
                response = requests.patch(url, headers=self.headers, json=update_data)
                
                if response.status_code == 200:
                    app.logger.info(f"Submission {submission_id} status updated to {status} using field '{field_name}'")
                    return True
                else:
                    app.logger.debug(f"Failed to update with field '{field_name}': {response.status_code} - {response.text}")
            
            # If no field worked, log the error and return False
            app.logger.error(f"Failed to update submission status with any field name. Last response: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            app.logger.error(f"Error updating submission status: {str(e)}")
            return False

    def delete_submission(self, submission_id):
        if not self.api_token:
            return False

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"
            
            response = requests.delete(url, headers=self.headers)
            return response.status_code == 200
        except Exception as e:
            app.logger.error(f"Error deleting submission: {str(e)}")
            return False

    def get_all_clubs_from_airtable(self):
        """Fetch all clubs from Airtable"""
        if not self.api_token:
            app.logger.error("Cannot fetch clubs from Airtable: API token not configured")
            return []

        try:
            app.logger.info("Starting to fetch all clubs from Airtable")
            app.logger.debug(f"Using Airtable URL: {self.clubs_base_url}")
            all_records = []
            offset = None
            page_count = 0
            
            while True:
                page_count += 1
                params = {}
                if offset:
                    params['offset'] = offset
                
                app.logger.debug(f"Fetching page {page_count} with offset: {offset}")
                response = requests.get(self.clubs_base_url, headers=self.headers, params=params)
                app.logger.debug(f"Page {page_count} response status: {response.status_code}")
                
                if response.status_code != 200:
                    app.logger.error(f"Airtable API error on page {page_count}: {response.status_code} - {response.text}")
                    app.logger.error(f"Request headers: {self.headers}")
                    app.logger.error(f"Request params: {params}")
                    break
                
                try:
                    data = response.json()
                    page_records = data.get('records', [])
                    all_records.extend(page_records)
                    app.logger.debug(f"Page {page_count}: Retrieved {len(page_records)} records, total so far: {len(all_records)}")
                    
                    offset = data.get('offset')
                    if not offset:
                        app.logger.info(f"Completed fetching all clubs from Airtable. Total records: {len(all_records)}")
                        break
                except ValueError as json_error:
                    app.logger.error(f"Failed to parse Airtable JSON response on page {page_count}: {json_error}")
                    app.logger.error(f"Raw response content: {response.text[:500]}...")
                    break
            
            clubs = []
            app.logger.debug(f"Processing {len(all_records)} Airtable records into club data")
            for i, record in enumerate(all_records):
                fields = record.get('fields', {})
                app.logger.debug(f"Processing record {i+1}/{len(all_records)}: ID={record.get('id')}, Fields keys: {list(fields.keys())}")
                
                # Extract club information from Airtable fields
                club_data = {
                    'airtable_id': record['id'],
                    'name': fields.get('Club Name', '').strip(),
                    'leader_email': fields.get("Current Leaders' Emails", '').split(',')[0].strip() if fields.get("Current Leaders' Emails") else '',
                    'location': fields.get('Location', '').strip(),
                    'description': fields.get('Description', '').strip(),
                    'status': fields.get('Status', '').strip(),
                    'meeting_day': fields.get('Meeting Day', '').strip(),
                    'meeting_time': fields.get('Meeting Time', '').strip(),
                    'website': fields.get('Website', '').strip(),
                    'slack_channel': fields.get('Slack Channel', '').strip(),
                    'github': fields.get('GitHub', '').strip(),
                    'latitude': fields.get('Latitude'),
                    'longitude': fields.get('Longitude'),
                    'country': fields.get('Country', '').strip(),
                    'region': fields.get('Region', '').strip(),
                    'timezone': fields.get('Timezone', '').strip(),
                    'primary_leader': fields.get('Primary Leader', '').strip(),
                    'co_leaders': fields.get('Co-Leaders', '').strip(),
                    'meeting_notes': fields.get('Meeting Notes', '').strip(),
                    'club_applications_link': fields.get('Club Applications Link', '').strip(),
                }
                
                # Only include clubs with valid names and leader emails
                if club_data['name'] and club_data['leader_email']:
                    clubs.append(club_data)
                    app.logger.debug(f"Added valid club: {club_data['name']} ({club_data['leader_email']})")
                else:
                    app.logger.debug(f"Skipped invalid club record - Name: '{club_data['name']}', Email: '{club_data['leader_email']}'")
            
            app.logger.info(f"Successfully processed {len(clubs)} valid clubs from {len(all_records)} Airtable records")
            return clubs
            
        except Exception as e:
            app.logger.error(f"Error fetching clubs from Airtable: {str(e)}")
            return []

    def sync_club_with_airtable(self, club_id, airtable_data):
        """Sync a specific club with Airtable data"""
        try:
            app.logger.info(f"Starting sync for club ID {club_id} with Airtable data")
            app.logger.debug(f"Airtable data keys: {list(airtable_data.keys()) if airtable_data else 'None'}")
            
            club = Club.query.get(club_id)
            if not club:
                app.logger.error(f"Club with ID {club_id} not found in database")
                return False
            
            app.logger.debug(f"Found club: {club.name} (current location: {club.location})")
            
            # Update club fields with Airtable data
            if 'name' in airtable_data and airtable_data['name']:
                filtered_name = filter_profanity_comprehensive(airtable_data['name'])
                club.name = filtered_name
            else:
                club.name = club.name
            club.location = airtable_data.get('location', club.location)
            if 'description' in airtable_data and airtable_data['description']:
                filtered_description = filter_profanity_comprehensive(airtable_data['description'])
                club.description = filtered_description
            else:
                club.description = club.description
            
            # Store additional Airtable metadata as JSON in a new field
            club.airtable_data = json.dumps({
                'airtable_id': airtable_data.get('airtable_id'),
                'status': airtable_data.get('status'),
                'meeting_day': airtable_data.get('meeting_day'),
                'meeting_time': airtable_data.get('meeting_time'),
                'website': airtable_data.get('website'),
                'slack_channel': airtable_data.get('slack_channel'),
                'github': airtable_data.get('github'),
                'latitude': airtable_data.get('latitude'),
                'longitude': airtable_data.get('longitude'),
                'country': airtable_data.get('country'),
                'region': airtable_data.get('region'),
                'timezone': airtable_data.get('timezone'),
                'primary_leader': airtable_data.get('primary_leader'),
                'co_leaders': airtable_data.get('co_leaders'),
                'meeting_notes': airtable_data.get('meeting_notes'),
                'club_applications_link': airtable_data.get('club_applications_link'),
            })
            
            club.updated_at = datetime.now(timezone.utc)
            app.logger.debug(f"Updated club fields for {club.name}")
            
            db.session.commit()
            app.logger.info(f"Successfully synced club {club_id} ({club.name}) with Airtable data")
            return True
            
        except Exception as e:
            app.logger.error(f"Error syncing club {club_id} with Airtable: {str(e)}")
            app.logger.error(f"Exception type: {type(e).__name__}")
            app.logger.error(f"Exception details: {str(e)}")
            db.session.rollback()
            return False

    def create_club_from_airtable(self, airtable_data):
        """Create a new club from Airtable data"""
        try:
            app.logger.info(f"Creating new club from Airtable data")
            app.logger.debug(f"Airtable data: {airtable_data}")
            
            # Find or create leader by email
            leader_email = airtable_data.get('leader_email')
            if not leader_email:
                app.logger.error("Cannot create club: no leader email provided in Airtable data")
                return None
            
            app.logger.debug(f"Looking for leader with email: {leader_email}")
            
            leader = User.query.filter_by(email=leader_email).first()
            if not leader:
                # Create a placeholder leader account
                username = leader_email.split('@')[0]
                # Ensure username is unique
                counter = 1
                original_username = username
                while User.query.filter_by(username=username).first():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                leader = User(
                    username=username,
                    email=leader_email,
                    first_name=airtable_data.get('primary_leader', '').split(' ')[0] if airtable_data.get('primary_leader') else '',
                    last_name=' '.join(airtable_data.get('primary_leader', '').split(' ')[1:]) if airtable_data.get('primary_leader') else ''
                )
                leader.set_password(secrets.token_urlsafe(16))  # Random password
                db.session.add(leader)
                db.session.flush()
            
            # Create club
            filtered_name = filter_profanity_comprehensive(airtable_data.get('name'))
            
            # Check for duplicate club names
            existing_club = Club.query.filter_by(name=filtered_name).first()
            if existing_club:
                app.logger.warning(f"Skipping club creation from Airtable - duplicate name: {filtered_name}")
                return None
            
            default_desc = f"Official {filtered_name} Hack Club"
            club_desc = airtable_data.get('description', default_desc)
            filtered_description = filter_profanity_comprehensive(club_desc)
            club = Club(
                name=filtered_name,
                description=filtered_description,
                location=airtable_data.get('location'),
                leader_id=leader.id,
                airtable_data=json.dumps({
                    'airtable_id': airtable_data.get('airtable_id'),
                    'status': airtable_data.get('status'),
                    'meeting_day': airtable_data.get('meeting_day'),
                    'meeting_time': airtable_data.get('meeting_time'),
                    'website': airtable_data.get('website'),
                    'slack_channel': airtable_data.get('slack_channel'),
                    'github': airtable_data.get('github'),
                    'latitude': airtable_data.get('latitude'),
                    'longitude': airtable_data.get('longitude'),
                    'country': airtable_data.get('country'),
                    'region': airtable_data.get('region'),
                    'timezone': airtable_data.get('timezone'),
                    'primary_leader': airtable_data.get('primary_leader'),
                    'co_leaders': airtable_data.get('co_leaders'),
                    'meeting_notes': airtable_data.get('meeting_notes'),
                    'club_applications_link': airtable_data.get('club_applications_link'),
                })
            )
            club.generate_join_code()
            
            db.session.add(club)
            db.session.commit()
            
            app.logger.info(f"Successfully created club '{club.name}' from Airtable data (ID: {club.id})")
            return club
            
        except Exception as e:
            app.logger.error(f"Error creating club from Airtable data: {str(e)}")
            app.logger.error(f"Exception type: {type(e).__name__}")
            app.logger.error(f"Airtable data that caused error: {airtable_data}")
            db.session.rollback()
            return None

    def update_club_in_airtable(self, airtable_record_id, fields):
        """Update a specific club record in Airtable"""
        if not self.api_token or not airtable_record_id:
            return False
            
        try:
            update_url = f"{self.clubs_base_url}/{airtable_record_id}"
            payload = {'fields': fields}
            
            response = requests.patch(update_url, headers=self.headers, json=payload)
            
            if response.status_code == 200:
                return True
            else:
                app.logger.error(f"Airtable update error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"Error updating Airtable record: {str(e)}")
            return False

    def send_email_verification(self, email):
        """Send email verification code to Airtable for automation with retry logic"""
        if not self.api_token:
            app.logger.error("Airtable API token not configured for email verification")
            return None
            
        # Generate 5-digit verification code
        verification_code = ''.join(secrets.choice(string.digits) for _ in range(5))
        
        # Retry logic for network timeouts
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # First, check if there's an existing pending verification for this email
                existing_params = {
                    'filterByFormula': f'AND({{Email}} = "{email}", {{Status}} = "Pending")'
                }
                
                existing_response = self._safe_request('GET', self.email_verification_url, headers=self.headers, params=existing_params, timeout=90)
                
                if existing_response.status_code == 200:
                    existing_data = existing_response.json()
                    existing_records = existing_data.get('records', [])
                    
                    # Update existing pending record instead of creating new one
                    if existing_records:
                        record_id = existing_records[0]['id']
                        update_url = f"{self.email_verification_url}/{record_id}"
                        
                        payload = {
                            'fields': {
                                'Code': verification_code,
                                'Status': 'Pending'
                            }
                        }
                        
                        response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload, timeout=90)
                    else:
                        # Create new verification record
                        payload = {
                            'records': [{
                                'fields': {
                                    'Email': email,
                                    'Code': verification_code,
                                    'Status': 'Pending'
                                }
                            }]
                        }
                        
                        response = self._safe_request('POST', self.email_verification_url, headers=self.headers, json=payload, timeout=90)
                else:
                    # Create new verification record if we can't check existing
                    payload = {
                        'records': [{
                            'fields': {
                                'Email': email,
                                'Code': verification_code,
                                'Status': 'Pending'
                            }
                        }]
                    }
                    
                    response = self._safe_request('POST', self.email_verification_url, headers=self.headers, json=payload, timeout=90)
                
                if response.status_code in [200, 201]:
                    app.logger.info(f"Email verification code sent for {email}")
                    return verification_code
                else:
                    app.logger.error(f"Failed to send email verification: {response.status_code} - {response.text}")
                    return None
                    
            except requests.exceptions.ReadTimeout as e:
                retry_count += 1
                app.logger.warning(f"Email verification timeout, attempt {retry_count}/{max_retries}: {str(e)}")
                if retry_count >= max_retries:
                    app.logger.error(f"Email verification failed after {max_retries} attempts due to timeout")
                    return None
                # Wait before retrying
                import time
                time.sleep(2 ** retry_count)  # Exponential backoff
                
            except Exception as e:
                app.logger.error(f"Exception sending email verification: {str(e)}")
                return None
                
        return None

    def verify_email_code(self, email, code):
        """Verify the email verification code"""
        if not self.api_token:
            app.logger.error("Airtable API token not configured for email verification")
            return False
            
        try:
            # Find the verification record
            filter_params = {
                'filterByFormula': f'AND({{Email}} = "{email}", {{Code}} = "{code}", {{Status}} = "Pending")'
            }
            
            response = self._safe_request('GET', self.email_verification_url, headers=self.headers, params=filter_params, timeout=90)
            
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                
                if records:
                    # Mark as verified
                    record_id = records[0]['id']
                    update_url = f"{self.email_verification_url}/{record_id}"
                    
                    payload = {
                        'fields': {
                            'Status': 'Verified'
                        }
                    }
                    
                    update_response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload, timeout=90)
                    
                    if update_response.status_code == 200:
                        app.logger.info(f"Email verification successful for {email}")
                        return True
                    else:
                        app.logger.error(f"Failed to update verification status: {update_response.status_code}")
                        return False
                else:
                    app.logger.warning(f"No pending verification found for {email} with code {code}")
                    return False
            else:
                app.logger.error(f"Error checking verification code: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"Exception verifying email code: {str(e)}")
            return False

    def check_email_code(self, email, code):
        """Check if email verification code is valid without marking as verified"""
        if not self.api_token:
            app.logger.error("Airtable API token not configured for email verification")
            return False
            
        try:
            # Find the verification record
            filter_params = {
                'filterByFormula': f'AND({{Email}} = "{email}", {{Code}} = "{code}", {{Status}} = "Pending")'
            }
            
            response = self._safe_request('GET', self.email_verification_url, headers=self.headers, params=filter_params, timeout=90)
            
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                
                if records:
                    app.logger.info(f"Email verification code check successful for {email}")
                    return True
                else:
                    app.logger.warning(f"No pending verification found for {email} with code {code}")
                    return False
            else:
                app.logger.error(f"Error checking verification code: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"Exception checking email code: {str(e)}")
            return False

    def sync_all_clubs_with_airtable(self):
        """Sync all clubs with Airtable data"""
        try:
            airtable_clubs = self.get_all_clubs_from_airtable()
            
            created_count = 0
            updated_count = 0
            
            for airtable_club in airtable_clubs:
                # Try to find existing club by leader email
                leader_email = airtable_club.get('leader_email')
                if not leader_email:
                    continue
                
                leader = User.query.filter_by(email=leader_email).first()
                existing_club = None
                
                if leader:
                    existing_club = Club.query.filter_by(leader_id=leader.id).first()
                
                if existing_club:
                    # Update existing club
                    if self.sync_club_with_airtable(existing_club.id, airtable_club):
                        updated_count += 1
                else:
                    # Create new club
                    new_club = self.create_club_from_airtable(airtable_club)
                    if new_club:
                        created_count += 1
            
            return {
                'success': True,
                'created': created_count,
                'updated': updated_count,
                'total_airtable_clubs': len(airtable_clubs)
            }
            
        except Exception as e:
            app.logger.error(f"Error syncing all clubs with Airtable: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def submit_project_data(self, submission_data):
        """Submit project submission data to Airtable"""
        if not self.api_token:
            app.logger.error("AIRTABLE: API token not configured")
            return None

        try:
            # Use YSWS Project Submission table
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            
            app.logger.info(f"AIRTABLE: Submitting to URL: {project_url}")

            fields = {
                'Address (Line 1)': submission_data.get('address_1', ''),
                'Birthday': submission_data.get('birthday', ''),
                'City': submission_data.get('city', ''),
                'Club Name': submission_data.get('club_name', ''),
                'Code URL': submission_data.get('github_url', ''),
                'Country': submission_data.get('country', ''),
                'Description': submission_data.get('project_description', ''),
                'Email': submission_data.get('email', ''),
                'First Name': submission_data.get('first_name', ''),
                'GitHub Username': submission_data.get('github_username', ''),
                'Hackatime Project': submission_data.get('project_name', ''),
                'Hours': float(str(submission_data.get('project_hours', '0')).strip()),
                'How can we improve?': submission_data.get('improve', ''),
                'How did you hear about this?': 'Through Club Leader Dashboard',
                'Last Name': submission_data.get('last_name', ''),
                'Leader Email': submission_data.get('leader_email', ''),
                'Playable URL': submission_data.get('live_url', ''),
                'State / Province': submission_data.get('state', ''),
                'Status': 'Pending',
                'What are we doing well?': submission_data.get('doing_well', ''),
                'ZIP / Postal Code': submission_data.get('zip', '')
            }

            # Remove empty fields to avoid validation issues
            fields = {k: v for k, v in fields.items() if v not in [None, '', []]}
            
            app.logger.info(f"AIRTABLE: Submitting fields: {list(fields.keys())}")
            app.logger.info(f"AIRTABLE: Project name: {fields.get('Hackatime Project', 'NOT_FOUND')}")
            app.logger.info(f"AIRTABLE: Hours: {fields.get('Hours', 'NOT_FOUND')}")

            payload = {'records': [{'fields': fields}]}
            
            response = self._safe_request('POST', project_url, headers=self.headers, json=payload)
            
            app.logger.info(f"AIRTABLE: Response status: {response.status_code}")
            if response.status_code not in [200, 201]:
                app.logger.error(f"AIRTABLE: Submission failed: {response.text}")
                return None
            
            result = response.json()
            app.logger.info(f"AIRTABLE: Successfully submitted project! Record ID: {result.get('records', [{}])[0].get('id', 'UNKNOWN')}")
            return result
            
        except Exception as e:
            app.logger.error(f"AIRTABLE: Exception in submit_project_data: {str(e)}")
            return None

    def get_ysws_project_submissions(self):
        """Get all YSWS project submissions from Airtable"""
        if not self.api_token:
            app.logger.error("AIRTABLE: API token not configured")
            return []

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            
            all_records = []
            offset = None
            
            while True:
                params = {}
                if offset:
                    params['offset'] = offset
                
                response = self._safe_request('GET', project_url, headers=self.headers, params=params)
                
                if response.status_code != 200:
                    app.logger.error(f"AIRTABLE: Failed to fetch project submissions: {response.text}")
                    break
                
                data = response.json()
                records = data.get('records', [])
                all_records.extend(records)
                
                offset = data.get('offset')
                if not offset:
                    break
            
            # Transform records to a more usable format
            submissions = []
            for record in all_records:
                fields = record.get('fields', {})
                submission = {
                    'id': record.get('id'),
                    'firstName': fields.get('First Name', ''),
                    'lastName': fields.get('Last Name', ''),
                    'email': fields.get('Email', ''),
                    'age': fields.get('Age', ''),
                    'codeUrl': fields.get('Code URL', ''),
                    'playableUrl': fields.get('Playable URL', ''),
                    'description': fields.get('Description', ''),
                    'githubUsername': fields.get('GitHub Username', ''),
                    'addressLine1': fields.get('Address (Line 1)', ''),
                    'addressLine2': fields.get('Address (Line 2)', ''),
                    'city': fields.get('City', ''),
                    'country': fields.get('Country', ''),
                    'zipCode': fields.get('ZIP / Postal Code', ''),
                    'birthday': fields.get('Birthday', ''),
                    'hackatimeProject': fields.get('Hackatime Project', ''),
                    'hours': fields.get('Hours', ''),
                    'grantAmount': fields.get('Grant Amount Override') or fields.get('Grant Amount', ''),
                    'clubName': fields.get('Club Name', ''),
                    'leaderEmail': fields.get('Leader Email', ''),
                    'status': fields.get('Status', 'Pending'),
                    'autoReviewStatus': fields.get('Auto Review Status', ''),
                    'decisionReason': fields.get('Decision Reason', ''),
                    'howDidYouHear': fields.get('How did you hear about this?', ''),
                    'whatAreWeDoingWell': fields.get('What are we doing well?', ''),
                    'howCanWeImprove': fields.get('How can we improve?', ''),
                    'screenshot': fields.get('Screenshot', ''),
                    'grantOverrideReason': fields.get('Grant Override Reason', ''),
                    'createdTime': record.get('createdTime', '')
                }
                
                # Handle screenshot attachment if it's an array
                if isinstance(submission['screenshot'], list) and len(submission['screenshot']) > 0:
                    submission['screenshot'] = submission['screenshot'][0].get('url', '')
                elif not isinstance(submission['screenshot'], str):
                    submission['screenshot'] = ''
                
                submissions.append(submission)
            
            app.logger.info(f"AIRTABLE: Fetched {len(submissions)} project submissions")
            return submissions
            
        except Exception as e:
            app.logger.error(f"AIRTABLE: Exception in get_ysws_project_submissions: {str(e)}")
            return []

    def update_ysws_project_submission(self, record_id, fields):
        """Update a YSWS project submission in Airtable"""
        if not self.api_token or not record_id:
            app.logger.error("AIRTABLE: API token not configured or no record ID provided")
            return False

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            update_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}/{record_id}'
            
            # Only include fields that we're allowed to update
            allowed_fields = {
                'Status', 'Decision Reason', 'Grant Amount Override', 'Auto Review Status', 'Grant Override Reason'
            }
            
            update_fields = {k: v for k, v in fields.items() if k in allowed_fields}
            
            payload = {'fields': update_fields}
            
            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)
            
            if response.status_code == 200:
                app.logger.info(f"AIRTABLE: Successfully updated project submission {record_id}")
                return True
            else:
                app.logger.error(f"AIRTABLE: Failed to update project submission: {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"AIRTABLE: Exception in update_ysws_project_submission: {str(e)}")
            return False

    def delete_ysws_project_submission(self, record_id):
        """Delete a YSWS project submission from Airtable"""
        if not self.api_token or not record_id:
            app.logger.error("AIRTABLE: API token not configured or no record ID provided")
            return False

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            delete_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}/{record_id}'
            
            response = self._safe_request('DELETE', delete_url, headers=self.headers)
            
            if response.status_code == 200:
                app.logger.info(f"AIRTABLE: Successfully deleted project submission {record_id}")
                return True
            else:
                app.logger.error(f"AIRTABLE: Failed to delete project submission: {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"AIRTABLE: Exception in delete_ysws_project_submission: {str(e)}")
            return False

    def submit_order(self, order_data):
        """Submit order to Orders table"""
        if not self.api_token:
            return None

        # Use Orders table in the shop base
        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        orders_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}'

        fields = {
            'Club Name': order_data.get('club_name', ''),
            'Leader First Name': order_data.get('leader_first_name', ''),
            'Leader Last Name': order_data.get('leader_last_name', ''),
            'Leader Email': order_data.get('leader_email', ''),
            'Club Member Amount': order_data.get('club_member_amount', 0),
            'Product(s)': order_data.get('products', ''),
            'Total Estimated Cost': order_data.get('total_estimated_cost', 0),
            'Delivery Address Line 1': order_data.get('delivery_address_line_1', ''),
            'Delivery Address Line 2': order_data.get('delivery_address_line_2', ''),
            'City': order_data.get('delivery_city', ''),
            'Delivery ZIP/Postal Code': order_data.get('delivery_zip', ''),
            'Delivery State/Area': order_data.get('delivery_state', ''),
            'Delivery Country': order_data.get('delivery_country', ''),
            'Special Notes': order_data.get('special_notes', ''),
            'Usage Reason': order_data.get('usage_reason', ''),
            'Order Sources': order_data.get('order_sources', []),
            'Shipment Status': 'Pending'
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(orders_url, headers=self.headers, json=payload)
            app.logger.debug(f"Airtable Orders response status: {response.status_code}")
            app.logger.debug(f"Airtable Orders response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                app.logger.error(f"Airtable Orders error: {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Exception submitting to Airtable Orders: {str(e)}")
            return None

    def get_orders_for_club(self, club_name):
        """Get all orders for a specific club"""
        if not self.api_token:
            return []

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        orders_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}'

        try:
            # Filter by club name
            params = {
                'filterByFormula': f"{{Club Name}} = '{club_name}'"
            }
            
            response = requests.get(orders_url, headers=self.headers, params=params)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                
                orders = []
                for record in records:
                    fields = record.get('fields', {})
                    orders.append({
                        'id': record['id'],
                        'club_name': fields.get('Club Name', ''),
                        'leader_first_name': fields.get('Leader First Name', ''),
                        'leader_last_name': fields.get('Leader Last Name', ''),
                        'leader_email': fields.get('Leader Email', ''),
                        'club_member_amount': fields.get('Club Member Amount', 0),
                        'products': fields.get('Product(s)', ''),
                        'total_estimated_cost': fields.get('Total Estimated Cost', 0),
                        'delivery_address_line_1': fields.get('Delivery Address Line 1', ''),
                        'delivery_address_line_2': fields.get('Delivery Address Line 2', ''),
                        'delivery_city': fields.get('City', ''),
                        'delivery_zip': fields.get('Delivery ZIP/Postal Code', ''),
                        'delivery_state': fields.get('Delivery State/Area', ''),
                        'delivery_country': fields.get('Delivery Country', ''),
                        'special_notes': fields.get('Special Notes', ''),
                        'usage_reason': fields.get('Usage Reason', ''),
                        'order_sources': fields.get('Order Sources', []),
                        'shipment_status': fields.get('Shipment Status', 'Pending'),
                        'created_time': record.get('createdTime', '')
                    })
                
                return orders
            else:
                app.logger.error(f"Failed to fetch orders: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            app.logger.error(f"Error fetching orders for club {club_name}: {str(e)}")
            return []

    def get_all_orders(self):
        """Get all orders for admin review"""
        if not self.api_token:
            return []

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        orders_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}'

        try:
            all_orders = []
            offset = None
            
            while True:
                params = {}
                if offset:
                    params['offset'] = offset
                
                response = requests.get(orders_url, headers=self.headers, params=params)
                if response.status_code == 200:
                    data = response.json()
                    records = data.get('records', [])
                    
                    for record in records:
                        fields = record.get('fields', {})
                        all_orders.append({
                            'id': record['id'],
                            'club_name': fields.get('Club Name', ''),
                            'leader_first_name': fields.get('Leader First Name', ''),
                            'leader_last_name': fields.get('Leader Last Name', ''),
                            'leader_email': fields.get('Leader Email', ''),
                            'club_member_amount': fields.get('Club Member Amount', 0),
                            'products': fields.get('Product(s)', ''),
                            'total_estimated_cost': fields.get('Total Estimated Cost', 0),
                            'delivery_address_line_1': fields.get('Delivery Address Line 1', ''),
                            'delivery_address_line_2': fields.get('Delivery Address Line 2', ''),
                            'delivery_city': fields.get('City', ''),
                            'delivery_zip': fields.get('Delivery ZIP/Postal Code', ''),
                            'delivery_state': fields.get('Delivery State/Area', ''),
                            'delivery_country': fields.get('Delivery Country', ''),
                            'special_notes': fields.get('Special Notes', ''),
                            'usage_reason': fields.get('Usage Reason', ''),
                            'order_sources': fields.get('Order Sources', []),
                            'shipment_status': fields.get('Shipment Status', 'Pending'),
                            'reviewer_reason': fields.get('Reviewer Reason', ''),
                            'created_time': record.get('createdTime', '')
                        })
                    
                    offset = data.get('offset')
                    if not offset:
                        break
                else:
                    app.logger.error(f"Failed to fetch all orders: {response.status_code} - {response.text}")
                    break
                    
            return all_orders
        except Exception as e:
            app.logger.error(f"Error fetching all orders: {str(e)}")
            return []

    def update_order_status(self, order_id, status, reviewer_reason):
        """Update order status and reviewer reason"""
        if not self.api_token:
            return False

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        update_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}/{order_id}'

        fields = {
            'Shipment Status': status,
            'Reviewer Reason': reviewer_reason
        }

        payload = {'fields': fields}

        try:
            response = requests.patch(update_url, headers=self.headers, json=payload)
            app.logger.debug(f"Airtable order update response status: {response.status_code}")
            app.logger.debug(f"Airtable order update response body: {response.text}")
            if response.status_code == 200:
                return response.json()
            else:
                app.logger.error(f"Airtable order update error: {response.text}")
                return False
        except Exception as e:
            app.logger.error(f"Exception updating order status: {str(e)}")
            return False

    def delete_order(self, order_id):
        """Delete an order record"""
        if not self.api_token:
            return False

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        delete_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}/{order_id}'

        try:
            response = requests.delete(delete_url, headers=self.headers)
            app.logger.debug(f"Airtable order delete response status: {response.status_code}")
            app.logger.debug(f"Airtable order delete response body: {response.text}")
            if response.status_code == 200:
                return response.json()
            else:
                app.logger.error(f"Airtable order delete error: {response.text}")
                return False
        except Exception as e:
            app.logger.error(f"Exception deleting order: {str(e)}")
            return False

    def log_gallery_post(self, post_title, description, photos, club_name, author_username):
        """Log gallery post to Airtable Gallery table"""
        if not self.api_token:
            app.logger.error("AIRTABLE: API token not configured for gallery logging")
            return False

        try:
            gallery_base_id = 'app7OFpfZceddfK17'  # Base ID provided by user
            gallery_table_name = urllib.parse.quote('Gallary')  # Table name provided by user (note the spelling)
            gallery_url = f'https://api.airtable.com/v0/{gallery_base_id}/{gallery_table_name}'
            
            # Format photos as comma-separated string (imgurl1, imgurl2, etc)
            photos_formatted = ', '.join(photos) if photos else ''
            
            fields = {
                'Post Title': post_title,
                'Description': description,
                'Photos': photos_formatted,
                'Club Name': club_name
            }
            
            payload = {'fields': fields}
            
            app.logger.info(f"AIRTABLE: Logging gallery post to {gallery_url}")
            app.logger.debug(f"AIRTABLE: Gallery post payload: {payload}")
            
            response = self._safe_request('POST', gallery_url, headers=self.headers, json=payload)
            
            app.logger.info(f"AIRTABLE: Gallery post response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                app.logger.info(f"AIRTABLE: Successfully logged gallery post! Record ID: {result.get('id', 'UNKNOWN')}")
                return True
            else:
                app.logger.error(f"AIRTABLE: Gallery post logging failed: {response.text}")
                return False
                
        except Exception as e:
            app.logger.error(f"AIRTABLE: Exception in log_gallery_post: {str(e)}")
            return False

airtable_service = AirtableService()

# Hackatime Service
class HackatimeService:
    def __init__(self):
        self.base_url = "https://hackatime.hackclub.com/api/v1"
        self.bypass_token = os.environ.get('HACKATIME_RL_BYPASS')

    def get_user_stats(self, api_key):
        if not api_key:
            app.logger.warning("get_user_stats: No API key provided")
            return None
        
        # Mask API key for logging (show first 8 and last 4 characters)
        masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        app.logger.info(f"get_user_stats: Making request to Hackatime API with key {masked_key}")
        
        url = f"{self.base_url}/users/my/stats?features=projects"
        headers = {"Authorization": f"Bearer {api_key}"}
        
        # Add rate limit bypass header if available
        if self.bypass_token:
            headers["Rack-Attack-Bypass"] = self.bypass_token
        
        try:
            app.logger.info(f"get_user_stats: Requesting URL: {url}")
            response = requests.get(url, headers=headers, timeout=10)
            app.logger.info(f"get_user_stats: Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                app.logger.info(f"get_user_stats: Success - received data with keys: {list(data.keys()) if isinstance(data, dict) else 'non-dict response'}")
                if isinstance(data, dict) and 'data' in data:
                    projects_count = len(data['data'].get('projects', []))
                    app.logger.info(f"get_user_stats: Found {projects_count} projects in response")
                else:
                    app.logger.warning("get_user_stats: Response missing 'data' key or not a dict")
                return data
            else:
                app.logger.error(f"get_user_stats: API request failed with status {response.status_code}")
                try:
                    error_body = response.text[:500]  # Limit error body length
                    app.logger.error(f"get_user_stats: Error response body: {error_body}")
                except:
                    app.logger.error("get_user_stats: Could not read error response body")
                return None
        except requests.exceptions.Timeout:
            app.logger.error("get_user_stats: Request timed out after 10 seconds")
            return None
        except requests.exceptions.RequestException as e:
            app.logger.error(f"get_user_stats: Request exception: {str(e)}")
            return None
        except Exception as e:
            app.logger.error(f"get_user_stats: Unexpected error: {str(e)}")
            return None

    def get_user_projects(self, api_key):
        masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        app.logger.info(f"get_user_projects: Starting for API key {masked_key}")
        
        stats = self.get_user_stats(api_key)
        if not stats:
            app.logger.warning("get_user_projects: get_user_stats returned None")
            return []
        
        if 'data' not in stats:
            app.logger.warning(f"get_user_projects: stats missing 'data' key. Stats keys: {list(stats.keys())}")
            return []
        
        projects = stats['data'].get('projects', [])
        app.logger.info(f"get_user_projects: Found {len(projects)} total projects")
        
        if not projects:
            app.logger.info("get_user_projects: No projects found in API response")
            return []
        
        # Log project details for debugging
        for i, project in enumerate(projects[:5]):  # Log first 5 projects
            project_name = project.get('name', 'unnamed')
            total_seconds = project.get('total_seconds', 0)
            app.logger.info(f"get_user_projects: Project {i+1}: '{project_name}' with {total_seconds} seconds")
        
        active_projects = [p for p in projects if p.get('total_seconds', 0) > 0]
        app.logger.info(f"get_user_projects: {len(active_projects)} projects have activity (>0 seconds)")
        
        active_projects.sort(key=lambda x: x.get('total_seconds', 0), reverse=True)
        
        for project in active_projects:
            total_seconds = project.get('total_seconds', 0)
            project['formatted_time'] = self.format_duration(total_seconds)
        
        app.logger.info(f"get_user_projects: Returning {len(active_projects)} active projects")
        return active_projects

    def format_duration(self, total_seconds):
        if total_seconds < 60:
            return f"{total_seconds}s"
        minutes = total_seconds // 60
        hours = minutes // 60
        days = hours // 24
        remaining_hours = hours % 24
        remaining_minutes = minutes % 60
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if remaining_hours > 0:
            parts.append(f"{remaining_hours}h")
        if remaining_minutes > 0:
            parts.append(f"{remaining_minutes}m")
        return " ".join(parts) if parts else "0m"

hackatime_service = HackatimeService()

# Hack Club Identity Service
class HackClubIdentityService:
    def __init__(self):
        self.base_url = HACKCLUB_IDENTITY_URL
        self.client_id = HACKCLUB_IDENTITY_CLIENT_ID
        self.client_secret = HACKCLUB_IDENTITY_CLIENT_SECRET

    def get_auth_url(self, redirect_uri, state=None):
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'basic_info address'
        }
        if state:
            params['state'] = state
        return f"{self.base_url}/oauth/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code, redirect_uri):
        data = {
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        try:
            response = requests.post(f'{self.base_url}/oauth/token', json=data)
            return response.json()
        except:
            return {'error': 'Request failed'}

    def get_user_identity(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(f'{self.base_url}/api/v1/me', headers=headers)
            if response.status_code == 200:
                data = response.json()
                app.logger.debug(f"Identity API response: {data}")
                return data
            else:
                app.logger.warning(f"Identity API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            app.logger.error(f"Identity API request failed: {str(e)}")
            return None

hackclub_identity_service = HackClubIdentityService()

# Slack OAuth Service
class SlackOAuthService:
    def __init__(self):
        self.client_id = SLACK_CLIENT_ID
        self.client_secret = SLACK_CLIENT_SECRET
        self.base_url = "https://slack.com/api"

    def get_auth_url(self, redirect_uri):
        params = {
            'client_id': self.client_id,
            'scope': 'users:read,users:read.email,users.profile:read',
            'user_scope': 'identity.basic,identity.email,identity.avatar',
            'redirect_uri': redirect_uri,
            'state': secrets.token_urlsafe(32)
        }
        session['oauth_state'] = params['state']
        return f"https://slack.com/oauth/v2/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code, redirect_uri):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri
        }
        try:
            response = requests.post('https://slack.com/api/oauth.v2.access', data=data)
            return response.json()
        except:
            return {'ok': False, 'error': 'Request failed'}

    def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        identity_url = f'{self.base_url}/users.identity'
        identity_response = requests.get(identity_url, headers=headers)
        if identity_response.status_code != 200:
            return None
        try:
            identity_data = identity_response.json()
            if not identity_data.get('ok'):
                return None
            user_id = identity_data['user']['id']
            profile_url = f'{self.base_url}/users.info'
            profile_params = {'user': user_id}
            profile_response = requests.get(profile_url, headers=headers, params=profile_params)
            if profile_response.status_code == 200:
                try:
                    profile_data = profile_response.json()
                    if profile_data.get('ok'):
                        identity_data['user']['profile'] = profile_data['user']['profile']
                except:
                    pass
            return identity_data
        except:
            return None

slack_oauth_service = SlackOAuthService()

# Custom Jinja2 filters for safe output
@app.template_filter('safe_css_color')
def safe_css_color_filter(value):
    """Template filter for safe CSS color output"""
    return sanitize_css_color(value)

@app.template_filter('safe_css_value')
def safe_css_value_filter(value):
    """Template filter for safe CSS value output"""
    return sanitize_css_value(value)

@app.template_filter('safe_html_attr')
def safe_html_attr_filter(value):
    """Template filter for safe HTML attribute output"""
    return sanitize_html_attribute(value)

@app.template_filter('safe_url')
def safe_url_filter(value):
    """Template filter for safe URL output"""
    return sanitize_url(value)

@app.route('/auth/slack')
@limiter.limit("10 per minute")
def slack_login():
    if is_authenticated():
        return redirect(url_for('dashboard'))
    
    if not SLACK_CLIENT_ID or not SLACK_CLIENT_SECRET:
        flash('Slack OAuth is not configured', 'error')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    auth_url = slack_oauth_service.get_auth_url(redirect_uri)
    return redirect(auth_url)

@app.route('/auth/slack/callback')
@limiter.limit("10 per minute")
def slack_callback():
    stored_state = session.get('oauth_state')
    received_state = request.args.get('state')
    
    if not stored_state or received_state != stored_state:
        session.clear()
        flash('Invalid OAuth state parameter. Please try again.', 'error')
        return redirect(url_for('login'))
    
    session.pop('oauth_state', None)
    
    code = request.args.get('code')
    if not code:
        error = request.args.get('error', 'Unknown error')
        flash(f'Slack authorization failed: {error}', 'error')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('slack_callback', _external=True, _scheme='https')
    token_data = slack_oauth_service.exchange_code(code, redirect_uri)
    
    if not token_data.get('ok'):
        error = token_data.get('error', 'Token exchange failed')
        flash(f'Slack authentication failed: {error}', 'error')
        return redirect(url_for('login'))
    
    user_token = None
    if 'authed_user' in token_data:
        user_token = token_data['authed_user'].get('access_token')
    
    if not user_token:
        user_token = token_data.get('access_token')
    
    if not user_token:
        flash('Failed to get user access token from Slack', 'error')
        return redirect(url_for('login'))
    
    user_info = slack_oauth_service.get_user_info(user_token)
    if not user_info or not user_info.get('ok'):
        if 'authed_user' in token_data:
            slack_user_id = token_data['authed_user']['id']
            user_info = {
                'ok': True,
                'user': {
                    'id': slack_user_id,
                    'name': f"user_{slack_user_id}",
                    'real_name': "",
                    'profile': {}
                }
            }
        else:
            flash('Failed to retrieve user information from Slack', 'error')
            return redirect(url_for('login'))
    
    slack_user = user_info['user']
    slack_user_id = slack_user['id']
    email = slack_user.get('email')
    name = slack_user.get('name', '')
    real_name = slack_user.get('real_name', '')
    profile = slack_user.get('profile', {})
    
    user = None
    try:
        if slack_user_id:
            user = User.query.filter_by(slack_user_id=slack_user_id).first()
        
        if not user and email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.slack_user_id = slack_user_id
                db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
            if slack_user_id:
                user = User.query.filter_by(slack_user_id=slack_user_id).first()
            if not user and email:
                user = User.query.filter_by(email=email).first()
        except Exception as e2:
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('login'))
    
    if user:
        app.logger.info(f"Slack OAuth: User {user.username} (ID: {user.id}) logging in from IP: {request.remote_addr}")
        login_user(user, remember=True)
        app.logger.info(f"Slack OAuth: Session created for user {user.username}: session_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
        flash(f'Welcome back, {user.username}!', 'success')
        
        # Check for pending join code
        pending_join_code = session.get('pending_join_code')
        if pending_join_code:
            session.pop('pending_join_code', None)
            return redirect(url_for('join_club_redirect') + f'?code={pending_join_code}')
        
        return redirect(url_for('dashboard'))
    else:
        session.clear()
        session['slack_signup_data'] = {
            'slack_user_id': slack_user_id,
            'email': email or '',
            'name': name,
            'real_name': real_name,
            'first_name': profile.get('first_name', ''),
            'last_name': profile.get('last_name', ''),
            'display_name': profile.get('display_name', ''),
            'image_url': profile.get('image_512', profile.get('image_192', ''))
        }
        return redirect(url_for('complete_slack_signup'))

@app.route('/complete-slack-signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def complete_slack_signup():
    if is_authenticated():
        return redirect(url_for('dashboard'))
    
    # Check if user registration is enabled
    if not SystemSettings.is_user_registration_enabled():
        flash('User registration is currently disabled.', 'error')
        return redirect(url_for('login'))
    
    slack_data = session.get('slack_signup_data')
    if not slack_data:
        flash('No Slack signup data found. Please try again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        data = request.get_json()
        
        username = data.get('username', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        birthday = data.get('birthday', '').strip()
        email = data.get('email', slack_data.get('email', '')).strip()
        password = data.get('password', '').strip()
        is_leader = data.get('is_leader', False)
        
        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters long'}), 400
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        if not first_name:
            return jsonify({'error': 'First name is required'}), 400
        
        if not password or len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        try:
            user = User(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                slack_user_id=slack_data['slack_user_id'],
                birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None,
                registration_ip=get_real_ip()
            )
            user.set_password(password)
            user.add_ip(get_real_ip())
            
            db.session.add(user)
            db.session.commit()
            
            session.pop('slack_signup_data', None)
            
            login_user(user, remember=True)
            
            if is_leader:
                return jsonify({
                    'success': True, 
                    'message': 'Account created! Now please verify your club leadership.',
                    'redirect': url_for('verify_leader')
                })
            
            return jsonify({'success': True, 'message': 'Account created successfully!'})
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    return render_template('slack_signup_complete.html', slack_data=slack_data)

# Hack Club Identity Routes
@api_route('/api/identity/authorize', methods=['GET'])
@login_required
@limiter.limit("20 per minute")
def hackclub_identity_authorize():
    if not HACKCLUB_IDENTITY_CLIENT_ID or not HACKCLUB_IDENTITY_CLIENT_SECRET:
        return jsonify({'error': 'Hack Club Identity is not configured'}), 500
    
    redirect_uri = url_for('hackclub_identity_callback', _external=True, _scheme='https')
    state = secrets.token_urlsafe(32)
    session['hackclub_identity_state'] = state
    
    auth_url = hackclub_identity_service.get_auth_url(redirect_uri, state)
    return jsonify({'url': auth_url})

# Maintenance mode middleware
@app.before_request
def check_maintenance_mode():
    """Check if maintenance mode is enabled and redirect non-admin users"""
    # Skip maintenance check for static files and API endpoints
    if request.endpoint and (request.endpoint.startswith('static') or '/api/' in request.path):
        return
    
    # Skip maintenance check for login and admin routes
    if request.endpoint in ['login', 'logout', 'maintenance'] or request.path.startswith('/admin/'):
        return
    
    try:
        # Check if maintenance mode is enabled
        if SystemSettings.is_maintenance_mode():
            # Allow admins to access even during maintenance
            current_user = get_current_user()
            if current_user and current_user.is_admin:
                return
            
            # Redirect non-admin users to maintenance page
            return render_template('maintenance.html')
    except Exception as e:
        # If there's an error checking maintenance mode, log it but don't block access
        app.logger.error(f"Error checking maintenance mode: {str(e)}")

@app.route('/maintenance')
def maintenance():
    """Display maintenance page"""
    return render_template('maintenance.html')

# Economy protection decorator
def economy_required(f):
    """Decorator to protect routes that require economy to be enabled"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not SystemSettings.is_economy_enabled():
                # Check if user is admin and admin override is enabled
                current_user = get_current_user()
                if current_user and current_user.is_admin and SystemSettings.is_admin_economy_override_enabled():
                    # Allow admin access when override is enabled
                    return f(*args, **kwargs)
                else:
                    if request.is_json:
                        return jsonify({'error': 'This feature is currently disabled.'}), 403
                    flash('This feature is currently disabled.', 'error')
                    return redirect(url_for('dashboard'))
        except Exception as e:
            app.logger.error(f"Error checking economy status: {str(e)}")
            # Allow access if we can't check the setting
        return f(*args, **kwargs)
    return decorated_function

# Context processor to make system settings available to all templates
@app.context_processor
def inject_system_settings():
    """Make system settings available to all templates"""
    try:
        maintenance_mode = SystemSettings.is_maintenance_mode()
        economy_enabled = SystemSettings.is_economy_enabled()
        admin_economy_override = SystemSettings.is_admin_economy_override_enabled()
        club_creation_enabled = SystemSettings.is_club_creation_enabled()
        user_registration_enabled = SystemSettings.is_user_registration_enabled()
        mobile_enabled = SystemSettings.is_mobile_enabled()
        heidi_enabled = SystemSettings.is_heidi_enabled()
        
        # For templates, economy is "enabled" if it's actually enabled OR if admin override is on and user is admin
        current_user = get_current_user()
        effective_economy_enabled = economy_enabled or (admin_economy_override and current_user and current_user.is_admin)
        
        return dict(
            maintenance_mode=maintenance_mode,
            economy_enabled=effective_economy_enabled,
            economy_actually_enabled=economy_enabled,
            admin_economy_override=admin_economy_override,
            club_creation_enabled=club_creation_enabled,
            user_registration_enabled=user_registration_enabled,
            mobile_enabled=mobile_enabled,
            heidi_enabled=heidi_enabled
        )
    except Exception as e:
        app.logger.error(f"Error getting system settings for templates: {str(e)}")
        return dict(maintenance_mode=False, economy_enabled=True, economy_actually_enabled=True, admin_economy_override=False, club_creation_enabled=True, user_registration_enabled=True, mobile_enabled=True, heidi_enabled=True)

@app.route('/identity/callback')
@limiter.limit("20 per minute")
def hackclub_identity_callback():
    stored_state = session.get('hackclub_identity_state')
    received_state = request.args.get('state')
    
    if not stored_state or received_state != stored_state:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='Invalid state parameter. Please try again.')
    
    session.pop('hackclub_identity_state', None)
    
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message=f'Authorization failed: {error}')
    
    if not code:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='No authorization code received')
    
    if not is_authenticated():
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='Please log in to complete identity verification')
    
    current_user = get_current_user()
    redirect_uri = url_for('hackclub_identity_callback', _external=True, _scheme='https')
    
    token_data = hackclub_identity_service.exchange_code(code, redirect_uri)
    
    if 'error' in token_data:
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message=f'Token exchange failed: {token_data.get("error", "Unknown error")}')
    
    # Store token
    current_user.identity_token = token_data.get('access_token')
    
    # Get user identity info
    identity_info = hackclub_identity_service.get_user_identity(current_user.identity_token)
    
    app.logger.info(f"Identity info received: {identity_info}")
    
    if identity_info and 'identity' in identity_info:
        verification_status = identity_info['identity'].get('verification_status', 'unverified')
        current_user.identity_verified = (verification_status == 'verified')
        
        db.session.commit()
        
        # Check for pending OAuth flow
        pending_oauth = session.get('pending_oauth')
        if pending_oauth:
            # Always complete the OAuth flow regardless of verification status
            session.pop('pending_oauth', None)
            
            auth_code = OAuthAuthorizationCode(
                user_id=current_user.id,
                application_id=pending_oauth['application_id'],
                redirect_uri=pending_oauth['redirect_uri'],
                state=pending_oauth['state']
            )
            auth_code.generate_code()
            auth_code.set_scopes(pending_oauth['scopes'])

            db.session.add(auth_code)
            db.session.commit()

            # Redirect back to client with authorization code
            redirect_url = f"{pending_oauth['redirect_uri']}?code={auth_code.code}"
            if pending_oauth['state']:
                redirect_url += f"&state={pending_oauth['state']}"

            return redirect(redirect_url)
        
        if verification_status == 'verified':
            return render_template('hackclub_identity_result.html', 
                                 status='success', 
                                 message='Identity verified successfully!')
        elif verification_status == 'pending':
            return render_template('hackclub_identity_result.html', 
                                 status='pending', 
                                 message='Your identity verification is pending review.')
        elif verification_status == 'rejected':
            rejection_reason = identity_info['identity'].get('rejection_reason', 'No reason provided')
            return render_template('hackclub_identity_result.html', 
                                 status='rejected', 
                                 message=f'Identity verification was rejected: {rejection_reason}')
    else:
        db.session.commit()
        return render_template('hackclub_identity_result.html', 
                             status='error', 
                             message='Failed to retrieve identity information')

@api_route('/api/identity/status', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def hackclub_identity_status():
    current_user = get_current_user()
    
    if not current_user.identity_token:
        return jsonify({'status': 'unverified', 'verified': False})
    
    identity_info = hackclub_identity_service.get_user_identity(current_user.identity_token)
    
    if identity_info and 'identity' in identity_info:
        verification_status = identity_info['identity'].get('verification_status', 'unverified')
        verified = (verification_status == 'verified')
        
        # Update database if status changed
        if current_user.identity_verified != verified:
            current_user.identity_verified = verified
            db.session.commit()
        
        return jsonify({
            'status': verification_status,
            'verified': verified,
            'rejection_reason': identity_info['identity'].get('rejection_reason')
        })
    
    return jsonify({'status': 'error', 'verified': False, 'message': 'Failed to check status'})

@api_route('/api/heidi/chat', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def heidi_chat():
    """Proxy endpoint for Heidi assistant chat"""
    current_user = get_current_user()
    
    # Check if Heidi is enabled
    if not SystemSettings.is_heidi_enabled():
        return jsonify({'error': 'Heidi assistant is currently disabled'}), 403
    
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        chat_history = data.get('chatHistory', [])
        console_logs = data.get('consoleLogs', [])
        action = data.get('action')  # For support contact functionality
        
        if not message and action != 'contact_support':
            return jsonify({'error': 'Message is required'}), 400
        
        # Smart support escalation function
        def should_escalate_to_support(user_message, ai_response):
            escalation_keywords = [
                'account locked', 'can\'t login', 'password reset', 'billing', 'payment',
                'refund', 'charged', 'subscription', 'delete account', 'gdpr', 'privacy',
                'data export', 'security issue', 'hacked', 'unauthorized', 'bug report',
                'doesn\'t work', 'broken', 'error 500', 'crash', 'database', 'technical issue',
                'talk to a human', 'human assistance', 'direct this convo', 'speak to someone',
                'real person', 'not working correctly', 'escalating', 'escalation'
            ]
            
            ai_uncertainty_phrases = [
                'i\'m not sure', 'i don\'t know', 'i can\'t help', 'unclear',
                'need more information', 'contact support', 'reach out to',
                'i\'m an ai assistant', 'i can\'t put you', 'i can\'t hand',
                'talk to a human', 'human assistance', 'direct this convo'
            ]
            
            user_lower = user_message.lower()
            ai_lower = ai_response.lower()
            
            # Check if user message contains escalation keywords
            for keyword in escalation_keywords:
                if keyword in user_lower:
                    return True
            
            # Check if AI response shows uncertainty
            for phrase in ai_uncertainty_phrases:
                if phrase in ai_lower:
                    return True
            
            return False
        
        def escalate_to_support():
            try:
                # Create AI summary of conversation
                summary_prompt = "Create a concise summary of this conversation focusing on the user's issue:\n\n"
                for msg in chat_history[-10:]:
                    if isinstance(msg, dict) and 'role' in msg and 'content' in msg:
                        summary_prompt += f"{msg['role']}: {msg['content']}\n"
                
                conversation_summary = f"User {current_user.username} requested human assistance via Heidi chatbot."
                
                # Try to generate AI summary using the same API endpoint
                try:
                    summary_response = requests.post(
                        'https://ai.hackclub.com/chat/completions',
                        json={
                            'messages': [{"role": "user", "content": summary_prompt}],
                            'model': 'openai/gpt-oss-20b',
                            'max_tokens': 300,
                            'temperature': 0.3
                        },
                        timeout=15
                    )
                    
                    if summary_response.status_code == 200:
                        summary_data = summary_response.json()
                        ai_summary = summary_data.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
                        if ai_summary:
                            conversation_summary = ai_summary
                            app.logger.info(f"Generated AI summary: {ai_summary}")
                    else:
                        app.logger.warning(f"AI summary API returned {summary_response.status_code}")
                except Exception as summary_error:
                    app.logger.warning(f"Failed to generate AI summary: {summary_error}")
                
                # Format console logs for Airtable
                formatted_logs = ""
                if console_logs:
                    try:
                        # Get the most recent logs (last 50 to avoid field length limits)
                        recent_logs = console_logs[-50:] if len(console_logs) > 50 else console_logs
                        log_lines = []
                        for log in recent_logs:
                            timestamp = log.get('timestamp', 'unknown')[:19].replace('T', ' ')  # Format: YYYY-MM-DD HH:MM:SS
                            level = log.get('level', 'log').upper()
                            message = log.get('message', '')[:500]  # Limit message length
                            log_lines.append(f"[{timestamp}] {level}: {message}")
                        formatted_logs = "\n".join(log_lines)
                    except Exception as log_error:
                        app.logger.warning(f"Failed to format console logs: {log_error}")
                        formatted_logs = "Error formatting console logs"
                
                # Submit to Airtable
                airtable_api_key = os.getenv('AIRTABLE_API_KEY') or os.getenv('AIRTABLE_TOKEN')
                if not airtable_api_key:
                    app.logger.error("AIRTABLE_API_KEY/AIRTABLE_TOKEN not configured")
                    return False
                
                try:
                    airtable_url = "https://api.airtable.com/v0/app7OFpfZceddfK17/Support"
                    airtable_headers = {
                        "Authorization": f"Bearer {airtable_api_key}",
                        "Content-Type": "application/json"
                    }
                    
                    # Try to get Slack ID from user attributes
                    slack_id = None
                    for attr_name in ['slack_id', 'slack_user_id', 'slack_username']:
                        if hasattr(current_user, attr_name):
                            slack_id = getattr(current_user, attr_name, None)
                            if slack_id:
                                break
                    
                    airtable_data = {
                        "fields": {
                            "User": current_user.username or "Unknown",
                            "Email": current_user.email or "no-email@example.com",
                            "Question": conversation_summary[:5000]  # Limit length
                        }
                    }
                    
                    if slack_id:
                        airtable_data["fields"]["Slack ID"] = str(slack_id)
                    
                    if formatted_logs:
                        airtable_data["fields"]["Logs"] = formatted_logs[:10000]  # Limit to 10k chars for Airtable
                    
                    app.logger.info(f"Submitting to Airtable: {airtable_data}")
                    
                    airtable_response = requests.post(
                        airtable_url, 
                        headers=airtable_headers, 
                        json=airtable_data,
                        timeout=15
                    )
                    
                    if airtable_response.status_code in [200, 201]:
                        app.logger.info(f"Successfully submitted to Airtable: {airtable_response.json()}")
                        return True
                    else:
                        app.logger.error(f"Airtable API error: {airtable_response.status_code} - {airtable_response.text}")
                        return False
                        
                except requests.RequestException as req_error:
                    app.logger.error(f"Request error to Airtable: {req_error}")
                    return False
                
            except Exception as e:
                app.logger.error(f"Error in support escalation: {str(e)}")
                import traceback
                app.logger.error(f"Traceback: {traceback.format_exc()}")
                return False
        
        # Load Heidi configuration
        try:
            with open('heidi_config.json', 'r') as f:
                heidi_config = json.load(f)
        except FileNotFoundError:
            return jsonify({'error': 'Heidi configuration not found'}), 500
        
        # Prepare system message with user context
        # Get current page context
        current_page = data.get('pageContext', 'Unknown')
        page_contexts = heidi_config.get('page_contexts', {})
        dashboard_features = heidi_config.get('dashboard_features', {})
        
        user_context = f"""
User Info:
- Username: {current_user.username}
- Email: {current_user.email}
- Admin: {current_user.is_admin}
- Dashboard URL: {request.host_url}
- Current Page: {current_page}

IMPORTANT: You have complete knowledge of the Hack Club Dashboard structure. Use ONLY these correct URLs when providing links:

Available Pages:
{json.dumps(page_contexts, indent=2)}

Dashboard Features by Section:
{json.dumps(dashboard_features, indent=2)}

When providing links, use the exact URLs from the page_contexts above. For club-specific pages, replace [ID] with the actual club ID from the current page context. Never make up URLs or link to external sites unless specifically asked about external resources.

Current page context: {page_contexts.get(current_page, f'User is on {current_page} - provide relevant help for this page')}
"""
        
        # Prepare messages for AI API with chat history
        messages = [
            {"role": "system", "content": heidi_config.get('system_prompt', '') + user_context}
        ]
        
        # Add chat history (limit to last 10 messages to avoid token limits)
        for hist_msg in chat_history[-10:]:
            if hist_msg.get('role') in ['user', 'assistant']:
                messages.append({
                    "role": hist_msg['role'],
                    "content": hist_msg['content']
                })
        
        # Add current message
        messages.append({"role": "user", "content": message})
        
        # Add escalate_to_support tool to the AI's available tools
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "escalate_to_support",
                    "description": "Escalate to human support ONLY when: 1) User explicitly asks to talk to a human, 2) Critical issues like account suspended/locked, payment problems, login failures, 3) After you have ALREADY asked for error details AND provided troubleshooting steps that failed. Do NOT use immediately when user just says 'error' - gather details first.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "reason": {
                                "type": "string",
                                "description": "The specific reason for escalation (e.g., 'account suspended', 'user requested human help', 'troubleshooting failed')"
                            },
                            "issue_summary": {
                                "type": "string", 
                                "description": "Brief summary of the user's issue and steps already tried"
                            }
                        },
                        "required": ["reason", "issue_summary"]
                    }
                }
            }
        ]
        
        # Make request to ai.hackclub.com with model from config
        ai_response = requests.post(
            'https://ai.hackclub.com/chat/completions',
            json={
                'messages': messages,
                'model': heidi_config.get('model', 'openai/gpt-oss-20b'),
                'max_tokens': 1000,
                'temperature': 0.7,
                'tools': tools,
                'tool_choice': 'auto'
            },
            timeout=30
        )
        
        if ai_response.status_code == 200:
            ai_data = ai_response.json()
            choice = ai_data.get('choices', [{}])[0]
            message_data = choice.get('message', {})
            assistant_message = message_data.get('content', 'Sorry, I could not process your request.')
            
            # Check if AI wants to use the escalate_to_support tool
            tool_calls = message_data.get('tool_calls', [])
            if tool_calls:
                for tool_call in tool_calls:
                    if tool_call.get('function', {}).get('name') == 'escalate_to_support':
                        # Execute the escalation
                        tool_args = tool_call.get('function', {}).get('arguments', '{}')
                        try:
                            import json as json_lib
                            args = json_lib.loads(tool_args) if isinstance(tool_args, str) else tool_args
                            escalation_reason = args.get('reason', 'User requested support')
                            issue_summary = args.get('issue_summary', 'No summary provided')
                            
                            app.logger.info(f"Escalation triggered - Reason: {escalation_reason}, Summary: {issue_summary}")
                            
                            escalation_success = escalate_to_support()
                            if escalation_success:
                                escalation_message = "I've forwarded this to our support team - they'll reach out via email or Slack soon! 📞"
                            else:
                                escalation_message = "Having trouble connecting to support right now. Please email clubs@hackclub.com directly. 📧"
                            
                            # Return the escalation message instead of or in addition to the assistant message
                            if assistant_message and assistant_message != 'Sorry, I could not process your request.':
                                assistant_message = assistant_message + "\n\n" + escalation_message
                            else:
                                assistant_message = escalation_message
                        except Exception as tool_error:
                            app.logger.error(f"Error processing escalation tool call: {tool_error}")
                            assistant_message = "I've noted your request for help. Please email clubs@hackclub.com for assistance. 📧"
                        break
            
            # Clean up any thinking tags or extra content that might be in the response
            if assistant_message and '<thinking>' in assistant_message and '</thinking>' in assistant_message:
                # Remove thinking tags and everything between them
                import re
                assistant_message = re.sub(r'<thinking>.*?</thinking>', '', assistant_message, flags=re.DOTALL).strip()
            
            # Remove any other debug markers
            if assistant_message and assistant_message.startswith('Okay,') and 'I should respond' in assistant_message:
                # Extract just the actual response part
                lines = assistant_message.split('\n')
                clean_response = []
                capturing = False
                for line in lines:
                    if not capturing and any(marker in line.lower() for marker in ['i\'m', 'hello', 'hi', 'thanks', 'great']):
                        capturing = True
                    if capturing and not any(debug in line.lower() for debug in ['should respond', 'keeping it', 'make sure', 'let me']):
                        clean_response.append(line.strip())
                if clean_response:
                    assistant_message = ' '.join(clean_response).strip()
            
            return jsonify({
                'success': True,
                'response': assistant_message
            })
        else:
            app.logger.error(f"AI API error: {ai_response.status_code} - {ai_response.text}")
            return jsonify({'error': 'Failed to get response from AI service'}), 500
            
    except requests.RequestException as e:
        app.logger.error(f"Request error in heidi_chat: {str(e)}")
        return jsonify({'error': 'Connection error to AI service'}), 500
    except Exception as e:
        app.logger.error(f"Error in heidi_chat: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/heidi/config', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_heidi_config():
    """Get Heidi configuration for frontend"""
    # Check if Heidi is enabled
    if not SystemSettings.is_heidi_enabled():
        return jsonify({'error': 'Heidi assistant is currently disabled'}), 403
    
    try:
        with open('heidi_config.json', 'r') as f:
            config = json.load(f)
        
        # Only return safe config items for frontend
        frontend_config = {
            'name': config.get('name', 'Heidi'),
            'description': config.get('description', 'Your AI assistant'),
            'avatar': config.get('avatar', '/static/assets/heidi-avatar.png'),
            'greeting': config.get('greeting', 'Hi! I\'m Heidi, your AI assistant. How can I help you today?'),
            'capabilities': config.get('capabilities', [])
        }
        
        return jsonify(frontend_config)
        
    except FileNotFoundError:
        return jsonify({
            'name': 'Heidi',
            'description': 'Your AI assistant',
            'avatar': '/static/assets/heidi-avatar.png',
            'greeting': 'Hi! I\'m Heidi, your AI assistant. How can I help you today?',
            'capabilities': []
        })
    except Exception as e:
        app.logger.error(f"Error getting Heidi config: {str(e)}")
        return jsonify({'error': 'Failed to load configuration'}), 500

# Routes
@app.route('/')
def index():
    if is_authenticated():
        return redirect(url_for('dashboard'))
    
    # Check if mobile device and redirect to login
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Redirect mobile users directly to login
    if (is_mobile or force_mobile) and not force_desktop:
        return redirect(url_for('login', mobile='true'))
    
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if is_authenticated():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = sanitize_string(request.form.get('email', ''), max_length=120).strip().lower()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'

        if not email or not password:
            flash('Email and password are required', 'error')
            # Check if mobile for error case
            user_agent = request.headers.get('User-Agent', '').lower()
            is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
            force_mobile = request.args.get('mobile', '').lower() == 'true'
            force_desktop = request.args.get('desktop', '').lower() == 'true'
            if (is_mobile or force_mobile) and not force_desktop:
                return render_template('login_mobile.html')
            else:
                return render_template('login.html')

        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            try:
                db.session.rollback()
                user = User.query.filter_by(email=email).first()
            except:
                flash('Database connection error. Please try again.', 'error')
                # Check if mobile for error case
                user_agent = request.headers.get('User-Agent', '').lower()
                is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
                force_mobile = request.args.get('mobile', '').lower() == 'true'
                force_desktop = request.args.get('desktop', '').lower() == 'true'
                if (is_mobile or force_mobile) and not force_desktop:
                    return render_template('login_mobile.html')
                else:
                    return render_template('login.html')

        if user and user.check_password(password):
            app.logger.info(f"User {user.username} (ID: {user.id}) logging in from IP: {request.remote_addr}")
            login_user(user, remember=remember_me)
            app.logger.info(f"Session created for user {user.username}: session_id={session.get('user_id')}, logged_in={session.get('logged_in')}")
            flash(f'Welcome back, {user.username}!', 'success')

            # Check for pending OAuth flow
            oauth_params = session.get('oauth_params')
            if oauth_params:
                session.pop('oauth_params', None)
                # Redirect back to OAuth authorize with original params
                query_string = '&'.join([f"{k}={v}" for k, v in oauth_params.items()])
                return redirect(url_for('oauth_authorize') + f'?{query_string}')

            # Check for pending join code
            pending_join_code = session.get('pending_join_code')
            if pending_join_code:
                session.pop('pending_join_code', None)
                return redirect(url_for('join_club_redirect') + f'?code={pending_join_code}')

            return redirect(url_for('dashboard'))
        else:
            log_security_event("FAILED_LOGIN", f"Failed login attempt for email: {email}", ip_address=get_real_ip())
            flash('Invalid email or password', 'error')

    # Check if mobile device
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Determine template to use
    if (is_mobile or force_mobile) and not force_desktop:
        return render_template('login_mobile.html')
    else:
        return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def forgot_password():
    """Request password reset - send verification code"""
    if is_authenticated():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = sanitize_string(request.form.get('email', ''), max_length=120).strip().lower()
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Don't reveal if user exists or not for security
            # Add delay to prevent timing attacks
            import time
            time.sleep(2)
            log_security_event("PASSWORD_RESET_ATTEMPT", f"Password reset attempted for non-existent email: {email}", ip_address=get_real_ip())
            return jsonify({'success': True, 'message': 'If an account exists with this email, a verification code will be sent.'})
        
        # Send verification code using existing airtable service
        verification_code = airtable_service.send_email_verification(email)
        
        if verification_code:
            log_security_event("PASSWORD_RESET_REQUESTED", f"Password reset code sent to: {email}", user_id=user.id, ip_address=get_real_ip())
            return jsonify({'success': True, 'message': 'Verification code sent to your email'})
        else:
            return jsonify({'success': False, 'message': 'Failed to send verification code. Please try again.'}), 500
    
    return render_template('forgot_password.html')

@app.route('/verify-reset-code', methods=['POST'])
@limiter.limit("10 per minute")
def verify_reset_code():
    """Verify reset code without resetting password"""
    if is_authenticated():
        return jsonify({'success': False, 'message': 'Already authenticated'}), 400
    
    data = request.get_json() if request.is_json else request.form
    email = sanitize_string(data.get('email', ''), max_length=120).strip().lower()
    verification_code = data.get('verification_code', '').strip()
    
    if not email or not verification_code:
        return jsonify({'success': False, 'message': 'Email and code are required'}), 400
    
    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400
    
    # Validate code format
    if len(verification_code) != 5 or not verification_code.isdigit():
        log_security_event("PASSWORD_RESET_INVALID_CODE", f"Invalid code format for email: {email}", ip_address=get_real_ip())
        return jsonify({'success': False, 'message': 'Invalid verification code format'}), 400
    
    # Check if user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        # Add delay to prevent timing attacks
        import time
        time.sleep(1)
        log_security_event("PASSWORD_RESET_INVALID_USER", f"Code verification attempted for non-existent email: {email}", ip_address=get_real_ip())
        return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
    
    # Check the code without marking it as verified (just validate it exists)
    is_code_valid = airtable_service.check_email_code(email, verification_code)
    
    if not is_code_valid:
        log_security_event("PASSWORD_RESET_FAILED_VERIFICATION", f"Failed code verification for email: {email}", user_id=user.id, ip_address=get_real_ip())
        return jsonify({'success': False, 'message': 'Invalid or expired verification code'}), 400
    
    log_security_event("PASSWORD_RESET_CODE_VERIFIED", f"Code verified for email: {email}", user_id=user.id, ip_address=get_real_ip())
    return jsonify({'success': True, 'message': 'Code verified successfully'})

@app.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def reset_password():
    """Reset password with verification code"""
    if is_authenticated():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        email = sanitize_string(data.get('email', ''), max_length=120).strip().lower()
        verification_code = data.get('verification_code', '').strip()
        new_password = data.get('new_password', '')
        
        if not email or not verification_code or not new_password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        # Validate code format
        if len(verification_code) != 5 or not verification_code.isdigit():
            log_security_event("PASSWORD_RESET_INVALID_CODE", f"Invalid code format for email: {email}", ip_address=get_real_ip())
            return jsonify({'success': False, 'message': 'Invalid verification code format'}), 400
        
        # Enhanced password strength validation
        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'}), 400
        
        if len(new_password) > 128:
            return jsonify({'success': False, 'message': 'Password is too long'}), 400
        
        # Check for common weak passwords
        weak_passwords = ['password', '12345678', 'qwerty123', 'password123', 'admin123', 'letmein123']
        if new_password.lower() in weak_passwords:
            return jsonify({'success': False, 'message': 'Password is too weak. Please choose a stronger password'}), 400
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            # Add delay to prevent timing attacks
            import time
            time.sleep(1)
            log_security_event("PASSWORD_RESET_INVALID_USER", f"Password reset attempted for non-existent email: {email}", ip_address=get_real_ip())
            return jsonify({'success': False, 'message': 'Invalid verification code'}), 400
        
        # Verify the code (this marks it as used)
        is_code_valid = airtable_service.verify_email_code(email, verification_code)
        
        if not is_code_valid:
            log_security_event("PASSWORD_RESET_FAILED", f"Failed password reset attempt with invalid code for email: {email}", user_id=user.id, ip_address=get_real_ip())
            return jsonify({'success': False, 'message': 'Invalid or expired verification code'}), 400
        
        try:
            # Check if new password is same as old password
            if user.check_password(new_password):
                return jsonify({'success': False, 'message': 'New password cannot be the same as your old password'}), 400
            
            user.set_password(new_password)
            db.session.commit()
            
            log_security_event("PASSWORD_RESET_SUCCESS", f"Password reset successful for user: {email}", user_id=user.id, ip_address=get_real_ip())
            
            # Invalidate all existing sessions for this user (if session management exists)
            # This prevents any potentially compromised sessions from being used
            
            return jsonify({'success': True, 'message': 'Password reset successful! You can now log in with your new password.'})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error resetting password: {str(e)}")
            log_security_event("PASSWORD_RESET_ERROR", f"Error resetting password for email: {email}", user_id=user.id, ip_address=get_real_ip())
            return jsonify({'success': False, 'message': 'Failed to reset password. Please try again.'}), 500
    
    return render_template('reset_password.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if is_authenticated():
        return redirect(url_for('dashboard'))
    
    # Check if user registration is enabled
    if not SystemSettings.is_user_registration_enabled():
        flash('User registration is currently disabled.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get and validate inputs with sanitization
        username = sanitize_string(request.form.get('username', ''), max_length=30).strip()
        email = sanitize_string(request.form.get('email', ''), max_length=120).strip()
        password = request.form.get('password', '')
        first_name = sanitize_string(request.form.get('first_name', ''), max_length=50).strip()
        last_name = sanitize_string(request.form.get('last_name', ''), max_length=50).strip()
        birthday = request.form.get('birthday', '')
        is_leader = request.form.get('is_leader') == 'on'

        # Validate username with security checks
        valid, result = validate_username(username)
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')
        username = result
        
        # Additional security validation for username
        valid, result = validate_input_with_security(username, "username")
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')
        username = result

        # Validate email
        valid, result = validate_email(email)
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')
        email = result

        # Validate password with stronger requirements
        valid, result = validate_password(password)
        if not valid:
            flash(result, 'error')
            return render_template('signup.html')

        # Validate names with security checks
        if first_name:
            valid, result = validate_name(first_name, "First name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            first_name = result
            
            # Security validation for first name
            valid, result = validate_input_with_security(first_name, "first_name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            first_name = result

        if last_name:
            valid, result = validate_name(last_name, "Last name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            last_name = result
            
            # Security validation for last name
            valid, result = validate_input_with_security(last_name, "last_name")
            if not valid:
                flash(result, 'error')
                return render_template('signup.html')
            last_name = result

        # Check for existing users
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('signup.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return render_template('signup.html')

        # Create user account first (regardless of leader status)
        user = User(
            username=username, 
            email=email, 
            first_name=first_name, 
            last_name=last_name, 
            birthday=datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None,
            registration_ip=get_real_ip()
        )
        user.set_password(password)
        user.add_ip(get_real_ip())  # Add to IP history
        db.session.add(user)
        db.session.commit()

        # Create audit log for signup
        create_audit_log(
            action_type='signup',
            description=f"New user {user.username} registered",
            user=user,
            details={
                'email': user.email,
                'is_leader': is_leader,
                'first_name': user.first_name,
                'last_name': user.last_name
            },
            category='auth'
        )

        if is_leader:
            # Log them in and redirect to leader verification
            login_user(user, remember=False)
            flash('Account created! Now please verify your club leadership.', 'info')
            return redirect(url_for('verify_leader'))

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/suspended')
@login_required
def suspended():
    return render_template('suspended.html')

@app.route('/dashboard')
@login_required
def dashboard():
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access your dashboard.', 'info')
        return redirect(url_for('login'))

    memberships = ClubMembership.query.filter_by(user_id=current_user.id).all()
    led_clubs = Club.query.filter_by(leader_id=current_user.id).all()

    # Create unique list of clubs (avoid duplicates if user is both leader and member)
    all_club_ids = set([club.id for club in led_clubs] + [m.club.id for m in memberships])
    if len(all_club_ids) == 1:
        club_id = list(all_club_ids)[0]
        return redirect(url_for('club_dashboard', club_id=club_id))

    return render_template('dashboard.html', memberships=memberships, led_clubs=led_clubs)

@app.route('/club-dashboard')
@app.route('/club-dashboard/<int:club_id>')
@login_required
def club_dashboard(club_id=None):
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access the club dashboard.', 'info')
        return redirect(url_for('login'))

    if club_id:
        club = Club.query.get_or_404(club_id)
        is_leader = club.leader_id == current_user.id
        is_co_leader = is_user_co_leader(club, current_user)
        is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
        is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin

        if not is_leader and not is_co_leader and not is_member and not is_admin_access:
            flash('You are not a member of this club', 'error')
            return redirect(url_for('dashboard'))
            
        # Check if club is suspended
        if club.is_suspended and not current_user.is_admin:
            flash('This club has been suspended', 'error')
            return redirect(url_for('dashboard'))
    else:
        club = Club.query.filter_by(leader_id=current_user.id).first()
        if not club:
            membership = ClubMembership.query.filter_by(user_id=current_user.id).first()
            if membership:
                club = membership.club

        if not club:
            flash('You are not a member of any club', 'error')
            return redirect(url_for('dashboard'))
            
        # Check if club is suspended
        if club.is_suspended and not current_user.is_admin:
            flash('This club has been suspended', 'error')
            return redirect(url_for('dashboard'))

    # Determine user role
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    membership = ClubMembership.query.filter_by(club_id=club.id, user_id=current_user.id).first()
    is_member = membership is not None
    is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin
    
    # Give admins full leader privileges when accessing via admin=true
    if is_admin_access:
        is_leader = True

    # Check if club is connected to directory - redirect if not (unless admin access or sync_immune)
    if not is_admin_access and not club.sync_immune:
        airtable_data = club.get_airtable_data()
        if not airtable_data or not airtable_data.get('airtable_id'):
            return redirect(url_for('club_connection_required', club_id=club.id))

    # Check if mobile device
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Check if mobile dashboard is enabled
    if (is_mobile or force_mobile) and not force_desktop and not SystemSettings.is_mobile_enabled():
        return render_template('mobile_unavailable.html', club_id=club.id)
    
    # Check if the club has any orders
    airtable_service = AirtableService()
    orders = airtable_service.get_orders_for_club(club.name)
    has_orders = len(orders) > 0
    
    # Check for recent token allocation to show toast notification
    if is_leader:
        # Token allocation notifications have been removed
        pass
    
    # Check if club has made a gallery post
    has_gallery_post = club_has_gallery_post(club.id)
    
    # Check if club is connected to directory
    airtable_data = club.get_airtable_data()
    is_connected_to_directory = airtable_data and airtable_data.get('airtable_id')

    # Get banner settings
    banner_settings = {
        'enabled': SystemSettings.get_setting('banner_enabled', 'false') == 'true',
        'title': SystemSettings.get_setting('banner_title', 'Design Contest'),
        'subtitle': SystemSettings.get_setting('banner_subtitle', 'Submit your creative projects and win amazing prizes!'),
        'icon': SystemSettings.get_setting('banner_icon', 'fas fa-palette'),
        'primary_color': SystemSettings.get_setting('banner_primary_color', '#ec3750'),
        'secondary_color': SystemSettings.get_setting('banner_secondary_color', '#d63146'),
        'background_color': SystemSettings.get_setting('banner_background_color', '#ffffff'),
        'text_color': SystemSettings.get_setting('banner_text_color', '#1a202c'),
        'link_url': SystemSettings.get_setting('banner_link_url', '/gallery'),
        'link_text': SystemSettings.get_setting('banner_link_text', 'Submit Entry')
    }
    
    # Route to appropriate template based on role
    if is_leader or is_co_leader or is_member:
        # All members (leaders, co-leaders, and regular members) get the same dashboard
        # Role-based visibility is handled in the templates themselves
        membership_date = membership.joined_at if membership else None
        
        
        # Pass additional role variables for template logic
        effective_is_leader = is_leader
        effective_is_co_leader = is_co_leader or is_admin_access  # Admin acts as co-leader minimum
        effective_can_manage = is_leader or is_co_leader or is_admin_access  # For general management tasks
        
        if (is_mobile or force_mobile) and not force_desktop:
            return render_template('club_dashboard_mobile.html', club=club, membership_date=membership_date, has_orders=has_orders, has_gallery_post=has_gallery_post, is_leader=is_leader, is_co_leader=is_co_leader, is_admin_access=is_admin_access, effective_is_leader=effective_is_leader, effective_is_co_leader=effective_is_co_leader, effective_can_manage=effective_can_manage, banner_settings=banner_settings, is_connected_to_directory=is_connected_to_directory)
        else:
            return render_template('club_dashboard.html', club=club, membership_date=membership_date, has_orders=has_orders, has_gallery_post=has_gallery_post, is_leader=is_leader, is_co_leader=is_co_leader, is_admin_access=is_admin_access, effective_is_leader=effective_is_leader, effective_is_co_leader=effective_is_co_leader, effective_can_manage=effective_can_manage, banner_settings=banner_settings, is_connected_to_directory=is_connected_to_directory)
    else:
        # User is not a member of this club
        flash('You are not a member of this club', 'error')
        return redirect(url_for('dashboard'))

@app.route('/club-connection-required/<int:club_id>')
@login_required
def club_connection_required(club_id):
    """Page shown when club is not connected to directory"""
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access this page.', 'info')
        return redirect(url_for('login'))

    club = Club.query.get_or_404(club_id)

    # Check if user has any relation to this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin

    if not is_leader and not is_co_leader and not is_member and not is_admin_access:
        flash('You are not a member of this club', 'error')
        return redirect(url_for('dashboard'))

    # If club is actually connected, redirect to dashboard
    airtable_data = club.get_airtable_data()
    if airtable_data and airtable_data.get('airtable_id'):
        return redirect(url_for('club_dashboard', club_id=club_id))

    # If admin accessing, just redirect to dashboard with admin access
    if is_admin_access:
        return redirect(url_for('club_dashboard', club_id=club_id, admin='true'))

    return render_template('club_connection_required.html', club=club, current_user=current_user)

@app.route('/club/<int:club_id>/poster-editor')
@login_required
def poster_editor(club_id):
    """Enhanced poster editor page - full canvas editor"""
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access the poster editor.', 'info')
        return redirect(url_for('login'))
    
    club = Club.query.get_or_404(club_id)
    
    # Check if user has access to this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin
    
    if not is_leader and not is_co_leader and not is_member and not is_admin_access:
        flash('You are not a member of this club', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if club is suspended
    if club.is_suspended and not current_user.is_admin:
        flash('This club has been suspended', 'error')
        return redirect(url_for('dashboard'))
    
    # Get list of stickers
    import os
    stickers_path = os.path.join(app.static_folder, 'assets', 'stickers')
    stickers = []
    if os.path.exists(stickers_path):
        stickers = [f for f in os.listdir(stickers_path) if f.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg'))]
    
    # Render the full poster editor
    return render_template('poster_editor.html', club=club, is_leader=is_leader, is_co_leader=is_co_leader, stickers=stickers)

@app.route('/verify-leader', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_leader():
    # Check if club creation is enabled
    if not SystemSettings.is_club_creation_enabled():
        flash('Club creation is currently disabled.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        data = request.get_json()
        step = data.get('step', 'send_verification')
        
        if step == 'send_verification':
            email = data.get('email', '').strip()

            if not email:
                return jsonify({'error': 'Email is required'}), 400

            # Check if Airtable is configured
            if not airtable_service.api_token:
                app.logger.error("Airtable verification failed: API token not configured")
                return jsonify({'error': 'Club verification service is not configured. Please contact support.'}), 500

            # Send email verification code
            app.logger.info(f"Sending email verification to: {email}")
            verification_code = airtable_service.send_email_verification(email)
            
            if verification_code:
                app.logger.info(f"Successfully sent verification code to {email}")
                # Store email in session for later steps
                session['leader_verification'] = {
                    'email': email,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                return jsonify({
                    'success': True, 
                    'message': 'Verification code sent! Check your email.',
                })
            else:
                app.logger.error(f"Failed to send verification code to {email}")
                return jsonify({'error': 'Failed to send email verification code. Please try again.'}), 500
        
        elif step == 'verify_email':
            email = data.get('email', '').strip()
            verification_code = data.get('verification_code', '').strip()
            
            if not email or not verification_code:
                return jsonify({'error': 'Email and verification code are required'}), 400
            
            # Verify the email code
            app.logger.info(f"Verifying email code for: {email}")
            is_code_valid = airtable_service.verify_email_code(email, verification_code)
            
            if is_code_valid:
                app.logger.info(f"Successfully verified email code for {email}")
                # Update session to mark email as verified
                session['leader_verification'] = {
                    'email': email,
                    'email_verified': True,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                session.modified = True
                
                return jsonify({
                    'success': True,
                    'message': 'Email verification successful!',
                })
            else:
                app.logger.warning(f"Failed to verify email code for {email}")
                return jsonify({'error': 'Invalid or expired verification code. Please check your email or request a new code.'}), 400
        
        elif step == 'get_clubs':
            email = data.get('email', '').strip()
            
            if not email:
                return jsonify({'error': 'Email is required'}), 400
            
            # Get clubs for this email from Airtable
            try:
                app.logger.info(f"Fetching clubs for leader email: {email}")
                email_filter_params = {
                    'filterByFormula': f'FIND("{email}", {{Current Leaders\' Emails}}) > 0'
                }
                app.logger.debug(f"Using filter formula: {email_filter_params['filterByFormula']}")
                
                response = requests.get(airtable_service.clubs_base_url, headers=airtable_service.headers, params=email_filter_params)
                app.logger.debug(f"Get clubs response status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    records = data.get('records', [])
                    app.logger.info(f"Found {len(records)} clubs for email {email}")
                    
                    clubs = []
                    for record in records:
                        fields = record.get('fields', {})
                        clubs.append({
                            'name': fields.get('Club Name', ''),
                            'location': fields.get('Location', ''),
                            'airtable_id': record['id']
                        })
                    
                    return jsonify({
                        'success': True,
                        'clubs': clubs
                    })
                else:
                    return jsonify({'error': 'Failed to fetch clubs from directory'}), 500
            except Exception as e:
                app.logger.error(f"Error fetching clubs for {email}: {str(e)}")
                return jsonify({'error': 'Failed to fetch clubs from directory'}), 500
        
        elif step == 'link_club':
            email = data.get('email', '').strip()
            club_name = data.get('club_name', '').strip()
            
            if not email or not club_name:
                return jsonify({'error': 'Email and club name are required'}), 400
            
            # Verify the club choice and store in session
            session['leader_verification'] = {
                'email': email,
                'club_name': club_name,
                'club_verified': True,
                'email_verified': True,
                'verified': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            session.modified = True
            
            return jsonify({
                'success': True,
                'message': 'Club linked successfully!'
            })

    return render_template('verify_leader.html')

@app.route('/club/<int:club_id>/shop')
@login_required
@economy_required
def club_shop(club_id):
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access the shop.', 'info')
        return redirect(url_for('login'))

    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader or co-leader of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        flash('Only club leaders and co-leaders can access the shop', 'error')
        return redirect(url_for('dashboard'))

    # Check if club has made a gallery post
    has_gallery_post = club_has_gallery_post(club.id)

    return render_template('club_shop.html', club=club, current_user=current_user, has_gallery_post=has_gallery_post)

@app.route('/club/<int:club_id>/orders')
@login_required
def club_orders(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader, co-leader, or member of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_co_leader and not is_member:
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('dashboard'))

    return render_template('club_orders.html', club=club)

@api_route('/api/club/<int:club_id>/shop-items', methods=['GET'])
@login_required
@economy_required
@limiter.limit("100 per hour")
def get_shop_items(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader or co-leader of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        # Fetch shop items from Airtable
        shop_base_id = 'app7OFpfZceddfK17'
        shop_table_name = 'Shop%20Items'
        shop_url = f'https://api.airtable.com/v0/{shop_base_id}/{shop_table_name}'
        
        headers = {
            'Authorization': f'Bearer {airtable_service.api_token}',
            'Content-Type': 'application/json'
        }
        
        # First, get all records
        response = requests.get(shop_url, headers=headers)
        
        if response.status_code != 200:
            app.logger.error(f"Airtable API error: {response.status_code} - {response.text}")
            return jsonify({'error': 'Failed to fetch shop items'}), 500
        
        data = response.json()
        all_records = data.get('records', [])
        
        # Second, get disabled items using filter
        disabled_items_url = f"{shop_url}?filterByFormula=NOT({{Enabled}})"
        disabled_response = requests.get(disabled_items_url, headers=headers)
        
        disabled_record_ids = set()
        if disabled_response.status_code == 200:
            disabled_data = disabled_response.json()
            disabled_records = disabled_data.get('records', [])
            disabled_record_ids = {record['id'] for record in disabled_records}
            app.logger.info(f"Found {len(disabled_record_ids)} disabled items: {[r.get('fields', {}).get('Item', 'Unknown') for r in disabled_records]}")
        else:
            app.logger.warning(f"Failed to fetch disabled items filter: {disabled_response.status_code}")
        
        app.logger.info(f"Fetched {len(all_records)} total shop items from Airtable, {len(disabled_record_ids)} are disabled")
        
        items = []
        for record in all_records:
            fields = record.get('fields', {})
            record_id = record['id']
            
            # Check if this item is disabled using the disabled IDs we fetched
            is_disabled = record_id in disabled_record_ids
            
            app.logger.info(f"🛍️ Shop item '{fields.get('Item', 'Unknown')}' (ID: {record_id}) - Disabled: {is_disabled}")
            
            # Extract image URL from Picture field
            picture_url = None
            if 'Picture' in fields and fields['Picture']:
                if isinstance(fields['Picture'], list) and len(fields['Picture']) > 0:
                    picture_url = fields['Picture'][0].get('url', '')
                elif isinstance(fields['Picture'], str):
                    picture_url = fields['Picture']
            
            item = {
                'id': record_id,
                'name': fields.get('Item', ''),
                'url': fields.get('Item URL', ''),
                'picture': picture_url,
                'price': fields.get('Rough Total Price', 0),
                'description': fields.get('Description', ''),
                'starred': bool(fields.get('Starred', False)),
                'enabled': not is_disabled,  # Enabled if NOT disabled
                'limited': bool(fields.get('Limited', False)),
                'source': fields.get('Source', 'Warehouse')  # Default to Warehouse if not specified
            }
            
            # Only include items that are enabled and have required fields
            if item['name'] and item['price'] and item['enabled']:
                items.append(item)
                app.logger.info(f"✅ Including shop item: {item['name']} (enabled: {item['enabled']})")
            else:
                app.logger.info(f"❌ Excluding shop item: {item['name']} (name: {bool(item['name'])}, price: {bool(item['price'])}, enabled: {item['enabled']})")
        
        return jsonify({'items': items})
            
    except Exception as e:
        app.logger.error(f"Error fetching shop items: {str(e)}")
        return jsonify({'error': 'Failed to fetch shop items'}), 500

@api_route('/api/admin/shop-items', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def get_admin_shop_items():
    current_user = get_current_user()
    
    # Check if user is admin or reviewer
    if not current_user.is_admin and not current_user.is_reviewer:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        # Fetch shop items from Airtable
        shop_base_id = 'app7OFpfZceddfK17'
        shop_table_name = 'Shop%20Items'
        shop_url = f'https://api.airtable.com/v0/{shop_base_id}/{shop_table_name}'
        
        headers = {
            'Authorization': f'Bearer {airtable_service.api_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(shop_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            records = data.get('records', [])
            
            items = {}
            for record in records:
                fields = record.get('fields', {})
                
                # Extract image URL from Picture field
                picture_url = None
                if 'Picture' in fields and fields['Picture']:
                    if isinstance(fields['Picture'], list) and len(fields['Picture']) > 0:
                        picture_url = fields['Picture'][0].get('url', '')
                    elif isinstance(fields['Picture'], str):
                        picture_url = fields['Picture']
                
                item_name = fields.get('Item', '')
                if item_name:
                    item_data = {
                        'id': record['id'],
                        'name': item_name,
                        'url': fields.get('Item URL', ''),
                        'picture': picture_url,
                        'price': fields.get('Rough Total Price', 0),
                        'description': fields.get('Description', ''),
                        'source': fields.get('Source', 'Warehouse')
                    }
                    
                    # Store with multiple keys for better matching
                    items[item_name.lower()] = item_data
                    
                    # Also store individual words for partial matching
                    words = item_name.lower().split()
                    for word in words:
                        if len(word) > 2:  # Only significant words
                            if word not in items:
                                items[word] = item_data
            
            return jsonify({'items': items})
        else:
            app.logger.error(f"Airtable API error: {response.status_code} - {response.text}")
            return jsonify({'error': 'Failed to fetch shop items'}), 500
            
    except Exception as e:
        app.logger.error(f"Error fetching admin shop items: {str(e)}")
        return jsonify({'error': 'Failed to fetch shop items'}), 500

@api_route('/api/club/<int:club_id>/orders', methods=['POST'])
@login_required
@economy_required
@limiter.limit("10 per hour")
def submit_order(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Check if user is leader or co-leader of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can place orders'}), 403

    data = request.get_json()

    # Validate required fields
    required_fields = ['delivery_address_line_1', 'delivery_city', 'delivery_zip', 'delivery_state', 'delivery_country', 'usage_reason', 'products', 'total_amount']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

    # Validate products field is not empty
    products = data.get('products', '').strip()
    if not products or products == '':
        return jsonify({'error': 'Cart is empty. Please add items to your cart before placing an order.'}), 400

    # Validate total amount
    try:
        total_amount = float(data.get('total_amount', 0))
        if total_amount <= 0:
            return jsonify({'error': 'Total amount must be greater than 0. Cart cannot be empty.'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid total amount format'}), 400

    # CRITICAL SECURITY: Check balance BEFORE submitting to Airtable
    # This prevents race conditions where balance is checked with stale data
    total_tokens = int(total_amount * 100)

    # Acquire lock on club record and verify sufficient balance
    try:
        club_locked = Club.query.filter_by(id=club_id).with_for_update().first()
        if not club_locked:
            return jsonify({'error': 'Club not found'}), 404

        if club_locked.tokens < total_tokens:
            db.session.rollback()
            return jsonify({
                'error': f'Insufficient balance. Required: {total_tokens} tokens, Available: {club_locked.tokens} tokens'
            }), 400

        # Check for duplicate recent orders (within last 10 seconds) to prevent double-click submissions
        recent_cutoff = datetime.utcnow() - timedelta(seconds=10)
        recent_duplicate = ClubTransaction.query.filter(
            ClubTransaction.club_id == club_id,
            ClubTransaction.transaction_type == 'purchase',
            ClubTransaction.reference_type == 'shop_order',
            ClubTransaction.amount == -total_tokens,
            ClubTransaction.created_at >= recent_cutoff
        ).first()

        if recent_duplicate:
            db.session.rollback()
            app.logger.warning(f"Duplicate order submission detected for club {club_id} by user {current_user.id}")
            return jsonify({'error': 'Duplicate order detected. Please wait before submitting another order.'}), 429

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error checking balance for order: {str(e)}")
        return jsonify({'error': 'Unable to verify balance. Please try again.'}), 500

    # Get club member count
    member_count = len(club.members) + 1  # +1 for the leader

    # Prepare order data for Airtable
    order_data = {
        'club_name': club.name,
        'leader_first_name': current_user.first_name or '',
        'leader_last_name': current_user.last_name or '',
        'leader_email': current_user.email,
        'club_member_amount': member_count,
        'products': products,
        'total_estimated_cost': total_amount,
        'delivery_address_line_1': data.get('delivery_address_line_1'),
        'delivery_address_line_2': data.get('delivery_address_line_2', ''),
        'delivery_city': data.get('delivery_city'),
        'delivery_zip': data.get('delivery_zip'),
        'delivery_state': data.get('delivery_state'),
        'delivery_country': data.get('delivery_country'),
        'special_notes': data.get('special_notes', ''),
        'usage_reason': data.get('usage_reason'),
        'order_sources': data.get('order_sources', [])
    }

    # Submit order to Airtable FIRST
    result = airtable_service.submit_order(order_data)

    if result:
        # Get the order ID from the result
        order_id = result.get('records', [{}])[0].get('id', '') if result.get('records') else ''

        # CRITICAL: Deduct tokens immediately after successful Airtable submission
        # This prevents token duplication exploits
        success, tx_result = create_club_transaction(
            club_id=club_id,
            transaction_type='purchase',
            amount=-total_tokens,  # Negative amount for debit
            description=f"Shop order: {products} (${total_amount})",
            user_id=current_user.id,
            reference_id=order_id,
            reference_type='shop_order',
            created_by=current_user.id
        )

        if success:
            app.logger.info(f"Shop order completed: {total_tokens} tokens deducted from club {club_id} for order {order_id}")
            # Refresh club to get updated balance
            db.session.refresh(club)
            return jsonify({
                'message': 'Order placed successfully! Tokens have been deducted from your club balance.',
                'new_balance': club.tokens,
                'order_id': order_id
            })
        else:
            # CRITICAL: If transaction fails after Airtable submission, log for manual review
            app.logger.error(f"CRITICAL: Order {order_id} submitted to Airtable but transaction failed: {tx_result}")
            app.logger.error(f"Manual intervention required for club {club_id}, order {order_id}")
            return jsonify({'error': f'Order submitted but payment processing failed. Please contact support immediately with order ID: {order_id}'}), 500
    else:
        return jsonify({'error': 'Failed to submit order. Please try again.'}), 500

@api_route('/api/club/<int:club_id>/orders', methods=['GET'])
@login_required
@economy_required
@limiter.limit("100 per hour")
def get_orders(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Check if user is leader, co-leader, or member of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        orders = airtable_service.get_orders_for_club(club.name)
        return jsonify({'orders': orders})
    except Exception as e:
        app.logger.error(f"Error fetching orders for club {club_id}: {str(e)}")
        return jsonify({'error': 'Failed to fetch orders'}), 500

@api_route('/api/club/<int:club_id>/cosmetics/purchase', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def purchase_cosmetic(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader or co-leader of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can purchase cosmetics'}), 403
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['cosmetic_type', 'cosmetic_name', 'cost']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400
    
    # Validate cost (should be in tokens)
    try:
        cost_tokens = float(data.get('cost', 0))
        if cost_tokens <= 0:
            return jsonify({'error': 'Cost must be greater than 0'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid cost format'}), 400
    
    # Convert cost from tokens to USD for balance check
    cost_usd = cost_tokens / 100
    
    # Note: Balance check moved to create_club_transaction for atomic operation
    
    try:
        # Check if cosmetic already exists for this club
        existing_cosmetic = ClubCosmetic.query.filter_by(
            club_id=club_id,
            cosmetic_type=data.get('cosmetic_type'),
            cosmetic_name=data.get('cosmetic_name')
        ).first()
        
        if existing_cosmetic:
            return jsonify({'error': 'This cosmetic has already been purchased for this club'}), 400
        
        # First attempt the transaction to ensure balance is available
        success, tx_result = create_club_transaction(
            club_id=club_id,
            transaction_type='purchase',
            amount=-int(cost_tokens),  # Negative amount for debit
            description=f"Cosmetic purchase: {data.get('cosmetic_name')} ({data.get('cosmetic_type')})",
            user_id=current_user.id,
            reference_type='cosmetic',
            created_by=current_user.id
        )
        
        if not success:
            return jsonify({'error': f'Purchase failed: {tx_result}'}), 400
        
        # Create cosmetic purchase record
        cosmetic = ClubCosmetic(
            club_id=club_id,
            cosmetic_id=sanitize_string(data.get('cosmetic_id', data.get('cosmetic_name', '').lower().replace(' ', '_')), 100),
            cosmetic_type=sanitize_string(data.get('cosmetic_type'), 50),
            cosmetic_name=sanitize_string(data.get('cosmetic_name'), 100),
            price_paid=cost_usd
        )
        
        db.session.add(cosmetic)
        db.session.commit()
        
        # Update transaction with cosmetic ID
        tx_result.reference_id = str(cosmetic.id)
        db.session.commit()
        
        app.logger.info(f"Cosmetic purchased: {data.get('cosmetic_name')} for club {club_id} by user {current_user.id}")
        
        # Refresh club to get updated balance
        db.session.refresh(club)
        
        return jsonify({
            'success': True,
            'message': f'{data.get("cosmetic_name")} purchased successfully!',
            'cosmetic': {
                'id': cosmetic.id,
                'type': cosmetic.cosmetic_type,
                'name': cosmetic.cosmetic_name,
                'cost': int(cost_tokens),  # Show original token cost
                'purchased_at': cosmetic.purchased_at.isoformat()
            },
            'new_balance': club.tokens
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error purchasing cosmetic for club {club_id}: {str(e)}")
        return jsonify({'error': 'Failed to purchase cosmetic. Please try again.'}), 500

@api_route('/api/club/<int:club_id>/cosmetics', methods=['GET'])
@login_required  
@limiter.limit("100 per hour")
def get_club_cosmetics(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader, co-leader, or member of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Get all cosmetics purchased by this club
        cosmetics = ClubCosmetic.query.filter_by(club_id=club_id).all()
        
        cosmetics_data = []
        for cosmetic in cosmetics:
            cosmetics_data.append({
                'id': cosmetic.id,
                'type': cosmetic.cosmetic_type,
                'name': cosmetic.cosmetic_name,
                'cost': int(cosmetic.price_paid * 100),  # Convert to tokens for display
                'purchased_at': cosmetic.purchased_at.isoformat()
            })
        
        return jsonify({'cosmetics': cosmetics_data})
        
    except Exception as e:
        app.logger.error(f"Error fetching cosmetics for club {club_id}: {str(e)}")
        return jsonify({'error': 'Failed to fetch cosmetics'}), 500

@api_route('/api/club/<int:club_id>/slack/settings', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_club_slack_settings(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader or co-leader
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can access Slack settings'}), 403
    
    try:
        slack_settings = ClubSlackSettings.query.filter_by(club_id=club_id).first()
        if slack_settings:
            return jsonify({'settings': slack_settings.to_dict()})
        else:
            return jsonify({'settings': None})
    except Exception as e:
        app.logger.error(f"Error fetching Slack settings for club {club_id}: {str(e)}")
        return jsonify({'error': 'Failed to fetch Slack settings'}), 500

@api_route('/api/club/<int:club_id>/slack/settings', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def update_club_slack_settings(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader or co-leader
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can update Slack settings'}), 403
    
    data = request.get_json()
    
    # Validate channel_id format (Slack channel IDs start with C)
    channel_id = data.get('channel_id', '').strip()
    if channel_id and not channel_id.startswith('C'):
        return jsonify({'error': 'Invalid channel ID format. Slack channel IDs should start with "C"'}), 400
    
    channel_name = sanitize_string(data.get('channel_name', ''), max_length=255).strip()
    
    try:
        slack_settings = ClubSlackSettings.query.filter_by(club_id=club_id).first()
        
        if slack_settings:
            # Update existing settings
            slack_settings.channel_id = channel_id
            slack_settings.channel_name = channel_name
            slack_settings.is_public = data.get('is_public', True)
            slack_settings.updated_at = datetime.now(timezone.utc)
        else:
            # Create new settings
            slack_settings = ClubSlackSettings(
                club_id=club_id,
                channel_id=channel_id,
                channel_name=channel_name,
                is_public=data.get('is_public', True)
            )
            db.session.add(slack_settings)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Slack settings updated successfully',
            'settings': slack_settings.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating Slack settings for club {club_id}: {str(e)}")
        return jsonify({'error': 'Failed to update Slack settings'}), 500

@api_route('/api/club/<int:club_id>/slack/invite', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
def invite_member_to_slack(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader or co-leader
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can invite members to Slack'}), 403
    
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    # Get club Slack settings
    slack_settings = ClubSlackSettings.query.filter_by(club_id=club_id).first()
    if not slack_settings or not slack_settings.channel_id:
        return jsonify({'error': 'Club Slack channel not configured. Please set up the channel first.'}), 400
    
    try:
        # Make request to Slack API
        slack_api_url = f'${os.getenv('HACKCLUB_MCG_API_URL')}/invite-to-channel'
        payload = {
            'email': email,
            'channel_id': slack_settings.channel_id,
            'api_key': os.getenv('HACKCLUB_MCG_API_KEY')
        }
        
        response = requests.post(slack_api_url, json=payload, timeout=30)
        
        if response.status_code == 200:
            app.logger.info(f"Successfully invited {email} to Slack channel {slack_settings.channel_id} for club {club_id}")
            return jsonify({
                'message': f'Successfully invited {email} to the Slack channel!',
                'channel_name': slack_settings.channel_name or 'your club channel'
            })
        else:
            app.logger.error(f"Slack invitation failed: {response.status_code} - {response.text}")
            return jsonify({
                'error': 'Failed to send Slack invitation. Please check the email address and try again.'
            }), 400
            
    except requests.RequestException as e:
        app.logger.error(f"Error making Slack API request: {str(e)}")
        return jsonify({'error': 'Failed to connect to Slack service. Please try again later.'}), 500
    except Exception as e:
        app.logger.error(f"Error inviting member to Slack for club {club_id}: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred. Please try again.'}), 500

@api_route('/api/club/<int:club_id>/slack/bulk-invite', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def bulk_invite_members_to_slack(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader or co-leader
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    
    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only club leaders and co-leaders can invite members to Slack'}), 403
    
    # Get club Slack settings
    slack_settings = ClubSlackSettings.query.filter_by(club_id=club_id).first()
    if not slack_settings or not slack_settings.channel_id:
        return jsonify({'error': 'Club Slack channel not configured. Please set up the channel first.'}), 400
    
    try:
        # Get all club members including leader
        member_emails = []
        
        # Add leader email
        member_emails.append(club.leader.email)
        
        # Add co-leader email if exists
        if club.co_leader:
            member_emails.append(club.co_leader.email)
        
        # Add member emails
        for membership in club.members:
            member_emails.append(membership.user.email)
        
        # Remove duplicates
        member_emails = list(set(member_emails))
        
        success_count = 0
        failed_invitations = []
        
        slack_api_url = f'${os.getenv('HACKCLUB_MCG_API_URL')}/invite-to-channel'
        
        for email in member_emails:
            try:
                payload = {
                    'email': email,
                    'channel_id': slack_settings.channel_id,
                    'api_key': os.getenv('HACKCLUB_MCG_API_KEY')
                }
                
                response = requests.post(slack_api_url, json=payload, timeout=30)
                
                if response.status_code == 200:
                    success_count += 1
                    app.logger.info(f"Successfully invited {email} to Slack channel {slack_settings.channel_id}")
                else:
                    failed_invitations.append(email)
                    app.logger.warning(f"Failed to invite {email} to Slack: {response.status_code} - {response.text}")
                    
            except Exception as e:
                failed_invitations.append(email)
                app.logger.error(f"Error inviting {email} to Slack: {str(e)}")
        
        return jsonify({
            'message': f'Bulk invitation completed! {success_count} members invited successfully.',
            'success_count': success_count,
            'total_members': len(member_emails),
            'failed_invitations': failed_invitations,
            'channel_name': slack_settings.channel_name or 'your club channel'
        })
        
    except Exception as e:
        app.logger.error(f"Error during bulk Slack invitation for club {club_id}: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred during bulk invitation. Please try again.'}), 500

@app.route('/club/<int:club_id>/project-submission')
@login_required
@economy_required
def project_submission(club_id):
    current_user = get_current_user()
    if not current_user:
        flash('Please log in to access project submission.', 'info')
        return redirect(url_for('login'))

    club = Club.query.get_or_404(club_id)
    
    # Check if user is leader, co-leader, or member of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        flash('You are not a member of this club', 'error')
        return redirect(url_for('dashboard'))
        
    # Check if club is suspended
    if club.is_suspended and not current_user.is_admin:
        flash('This club has been suspended', 'error')
        return redirect(url_for('dashboard'))

    # Pass user role and club data to template
    user_role = 'leader' if is_leader else ('co-leader' if is_co_leader else 'member')
    
    # Check if user has Hackatime API key configured
    has_hackatime = bool(current_user.hackatime_api_key and current_user.hackatime_api_key.strip())
    
    return render_template('project_submission.html', 
                         club=club, 
                         user_role=user_role,
                         is_leader=is_leader or is_co_leader,
                         has_hackatime=has_hackatime)

@app.route('/gallery')
@economy_required
def gallery():
    return render_template('gallery.html')

@app.route('/leaderboard')
@app.route('/leaderboard/<leaderboard_type>')
def leaderboard(leaderboard_type='total'):
    # Check if economy is enabled
    if not SystemSettings.is_economy_enabled():
        flash('The leaderboard is currently unavailable.', 'info')
        return redirect(url_for('dashboard'))
    
    try:
        from sqlalchemy import func
        
        # Get excluded clubs for this leaderboard type
        if leaderboard_type == 'total':
            exclusion_type = 'total_tokens'
        elif leaderboard_type == 'per_member':
            exclusion_type = 'tokens_per_member'
        else:  # most_members
            exclusion_type = 'most_members'
        
        exclusions = LeaderboardExclusion.query.filter_by(leaderboard_type=exclusion_type).all()
        excluded_club_ids = {exc.club_id for exc in exclusions}
        
        # Calculate total tokens for each club using transactions
        club_totals = db.session.query(
            ClubTransaction.club_id,
            func.sum(ClubTransaction.amount).label('total_tokens')
        ).group_by(ClubTransaction.club_id).subquery()
        
        if leaderboard_type == 'per_member':
            # Per-member leaderboard: projects per member
            # Get projects per club and member counts
            project_counts = db.session.query(
                ProjectSubmission.club_id,
                func.count(ProjectSubmission.id).label('total_projects')
            ).filter(
                ProjectSubmission.approved_at.isnot(None)  # Only approved projects
            ).group_by(ProjectSubmission.club_id).subquery()
            
            leaderboard_data = db.session.query(
                Club.id,
                Club.name,
                project_counts.c.total_projects,
                func.count(ClubMembership.id).label('member_count')
            ).outerjoin(
                project_counts, Club.id == project_counts.c.club_id
            ).outerjoin(
                ClubMembership, Club.id == ClubMembership.club_id
            ).filter(
                ~Club.id.in_(excluded_club_ids),
                project_counts.c.total_projects.isnot(None),
                Club.is_suspended == False  # Exclude suspended clubs
            ).group_by(
                Club.id, Club.name, project_counts.c.total_projects
            ).having(
                func.count(ClubMembership.id) >= 0  # Include clubs with 0+ members
            ).all()
            
            # Calculate projects per member and sort
            clubs = []
            for club_id, name, total_projects, member_count in leaderboard_data:
                actual_member_count = member_count + 1  # +1 for leader
                if total_projects and actual_member_count > 0:
                    projects_per_member = int(total_projects) / actual_member_count
                    clubs.append({
                        'id': club_id,
                        'name': name,
                        'total_projects': int(total_projects),
                        'member_count': actual_member_count,
                        'projects_per_member': round(projects_per_member, 2)
                    })
            
            # Sort by projects per member descending
            clubs.sort(key=lambda x: x['projects_per_member'], reverse=True)
            clubs = clubs[:50]  # Top 50
            
            # Add ranks
            for rank, club in enumerate(clubs, 1):
                club['rank'] = rank
                
            title = 'Projects Per Member'
            
        elif leaderboard_type == 'most_members':
            # Most members leaderboard
            leaderboard_data = db.session.query(
                Club.id,
                Club.name,
                func.count(ClubMembership.id).label('member_count')
            ).outerjoin(
                ClubMembership, Club.id == ClubMembership.club_id
            ).filter(
                ~Club.id.in_(excluded_club_ids),
                Club.is_suspended == False  # Exclude suspended clubs
            ).group_by(
                Club.id, Club.name
            ).order_by(
                func.count(ClubMembership.id).desc()
            ).limit(50).all()
            
            # Format the data
            clubs = []
            for rank, (club_id, name, member_count) in enumerate(leaderboard_data, 1):
                actual_member_count = member_count + 1  # +1 for leader
                clubs.append({
                    'rank': rank,
                    'id': club_id,
                    'name': name,
                    'member_count': actual_member_count,
                    'total_members': actual_member_count  # For display in template
                })
            
            title = 'Most Members'
            
        else:
            # Total tokens leaderboard (default)
            leaderboard_data = db.session.query(
                Club.id,
                Club.name,
                club_totals.c.total_tokens,
                func.count(ClubMembership.id).label('member_count')
            ).outerjoin(
                club_totals, Club.id == club_totals.c.club_id
            ).outerjoin(
                ClubMembership, Club.id == ClubMembership.club_id
            ).filter(
                ~Club.id.in_(excluded_club_ids),
                Club.is_suspended == False  # Exclude suspended clubs
            ).group_by(
                Club.id, Club.name, club_totals.c.total_tokens
            ).order_by(
                club_totals.c.total_tokens.desc().nullslast()
            ).limit(50).all()
            
            # Format the data
            clubs = []
            for rank, (club_id, name, total_tokens, member_count) in enumerate(leaderboard_data, 1):
                clubs.append({
                    'rank': rank,
                    'id': club_id,
                    'name': name,
                    'total_tokens': int(total_tokens) if total_tokens else 0,
                    'member_count': member_count + 1  # +1 for leader
                })
            
            title = 'Total Tokens'
        
        return render_template('leaderboard.html', 
                             clubs=clubs, 
                             leaderboard_type=leaderboard_type,
                             title=title)
    
    except Exception as e:
        app.logger.error(f"Error loading leaderboard: {str(e)}")
        return render_template('leaderboard.html', 
                             clubs=[], 
                             leaderboard_type=leaderboard_type or 'total',
                             title='Leaderboard',
                             error='Failed to load leaderboard data')

@app.route('/complete-leader-signup', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def complete_leader_signup():
    # Check if club creation is enabled
    if not SystemSettings.is_club_creation_enabled():
        flash('Club creation is currently disabled.', 'error')
        return redirect(url_for('index'))
    
    leader_verification = session.get('leader_verification')

    if not leader_verification or not leader_verification.get('club_verified') or not leader_verification.get('email_verified'):
        flash('Invalid verification session. Please complete both club and email verification.', 'error')
        return redirect(url_for('verify_leader'))

    if 'timestamp' in leader_verification:
        verification_time = datetime.fromisoformat(leader_verification['timestamp'])
        if (datetime.now(timezone.utc) - verification_time).total_seconds() > 3600:
            session.pop('leader_verification', None)
            flash('Verification expired. Please start over.', 'error')
            return redirect(url_for('verify_leader'))

    try:
        user = get_current_user()
        if not user:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))

        # Fetch full club data from Airtable
        email = leader_verification['email']
        club_data = None
        
        try:
            # Search for the club in Airtable using the verified email
            email_filter_params = {
                'filterByFormula': f'FIND("{email}", {{Current Leaders\' Emails}}) > 0'
            }
            
            response = requests.get(airtable_service.clubs_base_url, headers=airtable_service.headers, params=email_filter_params)
            
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                
                if records:
                    # Find the matching club record
                    club_name_lower = leader_verification['club_name'].lower()
                    for record in records:
                        fields = record.get('fields', {})
                        venue = fields.get('Club Name', '').lower()
                        
                        if (club_name_lower in venue or 
                            venue.find(club_name_lower) >= 0 or
                            any(word in venue for word in club_name_lower.split() if len(word) > 2)):
                            
                            club_data = {
                                'airtable_id': record['id'],
                                'name': fields.get('Club Name', '').strip(),
                                'location': fields.get('Location', '').strip(),
                                'description': fields.get('Description', '').strip() or f"Official {fields.get('Club Name', '')} Hack Club",
                                'status': fields.get('Status', '').strip(),
                                'meeting_day': fields.get('Meeting Day', '').strip(),
                                'meeting_time': fields.get('Meeting Time', '').strip(),
                                'website': fields.get('Website', '').strip(),
                                'slack_channel': fields.get('Slack Channel', '').strip(),
                                'github': fields.get('GitHub', '').strip(),
                                'latitude': fields.get('Latitude'),
                                'longitude': fields.get('Longitude'),
                                'country': fields.get('Address Country', '').strip(),
                                'region': fields.get('Continent', '').strip(),
                                'timezone': fields.get('Timezone', '').strip(),
                                'primary_leader': fields.get('Current Leader(s)', '').strip(),
                                'co_leaders': fields.get('Co-Leaders', '').strip(),
                                'meeting_notes': fields.get('Meeting Notes', '').strip(),
                                'club_applications_link': fields.get('Application Link', '').strip(),
                            }
                            break
        except Exception as e:
            app.logger.warning(f"Failed to fetch club data from Airtable: {str(e)}")

        # Check if user already has a club
        existing_club = Club.query.filter_by(leader_id=user.id).first()
        
        # Also check if this Airtable club already exists in the database
        # to prevent duplicate clubs for the same Airtable record
        existing_airtable_club = None
        if club_data:
            existing_airtable_club = Club.query.filter(
                Club.airtable_data.contains(f'"airtable_id": "{club_data["airtable_id"]}"')
            ).first()
        
        if existing_club:
            # User already has a club - update it with Airtable data if verification succeeded
            if club_data:
                # Update existing club with verified Airtable data
                filtered_name = filter_profanity_comprehensive(club_data['name'])
                filtered_description = filter_profanity_comprehensive(club_data['description'])
                existing_club.name = filtered_name
                existing_club.description = filtered_description
                existing_club.location = club_data['location']
                existing_club.airtable_data = json.dumps({
                    'airtable_id': club_data['airtable_id'],
                    'status': club_data['status'],
                    'meeting_day': club_data['meeting_day'],
                    'meeting_time': club_data['meeting_time'],
                    'website': club_data['website'],
                    'slack_channel': club_data['slack_channel'],
                    'github': club_data['github'],
                    'latitude': club_data['latitude'],
                    'longitude': club_data['longitude'],
                    'country': club_data['country'],
                    'region': club_data['region'],
                    'timezone': club_data['timezone'],
                    'primary_leader': club_data['primary_leader'],
                    'co_leaders': club_data['co_leaders'],
                    'meeting_notes': club_data['meeting_notes'],
                    'club_applications_link': club_data['club_applications_link'],
                })
                existing_club.updated_at = datetime.now(timezone.utc)
                
                # Update Airtable to mark club as onboarded to dashboard
                try:
                    airtable_update_url = f'https://api.airtable.com/v0/{airtable_service.clubs_base_id}/{airtable_service.clubs_table_id}/{club_data["airtable_id"]}'
                    airtable_update_data = {
                        'fields': {
                            'Onboarded to Dashboard': True
                        }
                    }
                    
                    response = requests.patch(airtable_update_url, 
                                            headers=airtable_service.headers, 
                                            json=airtable_update_data,
                                            timeout=30)
                    
                    if response.status_code != 200:
                        app.logger.error(f"Failed to update Airtable onboarded status: {response.text}")
                        
                except Exception as e:
                    app.logger.error(f"Error updating Airtable onboarded status: {str(e)}")
                
                db.session.commit()
                
                session.pop('leader_verification', None)
                flash(f'Club successfully verified and updated with official data from the Hack Club directory! Welcome to {club_data["name"]}!', 'success')
                return redirect(url_for('club_dashboard', club_id=existing_club.id))
            else:
                # User already has a club but verification failed to find it in Airtable
                session.pop('leader_verification', None)
                flash("We can't find your club in the Hack Club directory! Please verify your club information again to sync it properly.", 'warning')
                return redirect(url_for('club_dashboard', club_id=existing_club.id))
        else:
            # Check if another user already claimed this Airtable club
            if existing_airtable_club:
                session.pop('leader_verification', None)
                flash(f"This club has already been claimed by another user. If you believe this is an error, please contact support.", 'error')
                return redirect(url_for('verify_leader'))
            
            # Create new club after successful verification
            if not club_data:
                session.pop('leader_verification', None)
                flash("We can't find your club in the Hack Club directory! Please verify your club information again.", 'error')
                return redirect(url_for('verify_leader'))
            
            # Create club with Airtable data
            filtered_name = filter_profanity_comprehensive(club_data['name'])
            filtered_description = filter_profanity_comprehensive(club_data['description'])
            club = Club(
                name=filtered_name,
                description=filtered_description,
                location=club_data['location'],
                leader_id=user.id,
                airtable_data=json.dumps({
                    'airtable_id': club_data['airtable_id'],
                    'status': club_data['status'],
                    'meeting_day': club_data['meeting_day'],
                    'meeting_time': club_data['meeting_time'],
                    'website': club_data['website'],
                    'slack_channel': club_data['slack_channel'],
                    'github': club_data['github'],
                    'latitude': club_data['latitude'],
                    'longitude': club_data['longitude'],
                    'country': club_data['country'],
                    'region': club_data['region'],
                    'timezone': club_data['timezone'],
                    'primary_leader': club_data['primary_leader'],
                    'co_leaders': club_data['co_leaders'],
                    'meeting_notes': club_data['meeting_notes'],
                    'club_applications_link': club_data['club_applications_link'],
                })
            )
            club.generate_join_code()
            db.session.add(club)
            db.session.flush()  # Get the club ID before committing
            
            # Update Airtable to mark club as onboarded to dashboard
            try:
                airtable_update_url = f'https://api.airtable.com/v0/{airtable_service.clubs_base_id}/{airtable_service.clubs_table_id}/{club_data["airtable_id"]}'
                airtable_update_data = {
                    'fields': {
                        'Onboarded to Dashboard': True
                    }
                }
                
                response = requests.patch(airtable_update_url, 
                                        headers=airtable_service.headers, 
                                        json=airtable_update_data,
                                        timeout=30)
                
                if response.status_code != 200:
                    app.logger.error(f"Failed to update Airtable onboarded status: {response.text}")
                    
            except Exception as e:
                app.logger.error(f"Error updating Airtable onboarded status: {str(e)}")
            
            db.session.commit()
            
            session.pop('leader_verification', None)
            flash(f'Club linked successfully! Welcome to {club_data["name"]}!', 'success')
            return redirect(url_for('club_dashboard', club_id=club.id))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in complete_leader_signup: {str(e)}")
        flash('Database error. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/join-club')
def join_club_redirect():
    join_code = request.args.get('code')
    if not join_code:
        flash('Invalid join code', 'error')
        return redirect(url_for('dashboard'))

    if is_authenticated():
        current_user = get_current_user()
        club = Club.query.filter_by(join_code=join_code).first()
        if not club:
            flash('Invalid join code', 'error')
            return redirect(url_for('dashboard'))

        # Check if user is already the leader
        if club.leader_id == current_user.id:
            flash(f"You are the leader of {club.name}", 'info')
            return redirect(url_for('club_dashboard', club_id=club.id))

        existing_membership = ClubMembership.query.filter_by(
            user_id=current_user.id, club_id=club.id).first()

        if existing_membership:
            flash(f"You are already a member of {club.name}", 'info')
            return redirect(url_for('club_dashboard', club_id=club.id))

        new_membership = ClubMembership(
            user_id=current_user.id,
            club_id=club.id,
            role='member'
        )
        db.session.add(new_membership)
        db.session.commit()

        # Create audit log for club joining
        create_audit_log(
            action_type='club_join',
            description=f"User {current_user.username} joined club '{club.name}' using join code",
            user=current_user,
            target_type='club',
            target_id=str(club.id),
            details={
                'club_name': club.name,
                'join_code': join_code,
                'method': 'join_code'
            },
            severity='info',
            admin_action=False,
            category='club'
        )

        flash(f"You have successfully joined {club.name}!", 'success')
        return redirect(url_for('club_dashboard', club_id=club.id))
    else:
        session['pending_join_code'] = join_code
        flash('Please log in or sign up to join the club', 'info')
        return redirect(url_for('login'))

# Club Chat API Routes
@app.route('/api/club/<int:club_id>/chat/messages', methods=['GET'])
@login_required
def get_club_chat_messages(club_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin
        
        if not is_member and not is_admin_access:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get the last 50 messages (newest first)
        messages = ClubChatMessage.query.filter_by(club_id=club_id)\
            .order_by(ClubChatMessage.created_at.desc())\
            .limit(50)\
            .all()
        
        # Convert to dict and add permission info
        message_list = []
        for msg in reversed(messages):  # Reverse to show oldest first
            msg_dict = msg.to_dict()
            # Add permission to delete message
            msg_dict['can_delete'] = (
                msg.user_id == current_user.id or  # Own message
                club.leader_id == current_user.id or  # Leader can delete all
                club.co_leader_id == current_user.id  # Co-leader can delete all
            )
            # Add permission to edit message (only sender can edit)
            msg_dict['can_edit'] = (msg.user_id == current_user.id)
            message_list.append(msg_dict)
        
        return jsonify({'messages': message_list}), 200
        
    except Exception as e:
        app.logger.error(f"Error getting chat messages: {str(e)}")
        return jsonify({'error': 'Failed to load messages'}), 500

@app.route('/api/club/<int:club_id>/chat/messages', methods=['POST'])
@login_required
def send_club_chat_message(club_id):
    try:
        current_user = get_current_user()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        message_content = data.get('message', '').strip() if data.get('message') else ''
        image_url = data.get('image_url', '').strip() if data.get('image_url') else ''
        
        # Must have either message or image
        if not message_content and not image_url:
            return jsonify({'error': 'Message or image is required'}), 400
        
        # Sanitize message if provided
        if message_content:
            message_content = sanitize_string(message_content, max_length=1000)
        
        # Validate image URL if provided (log for debugging)
        if image_url:
            app.logger.info(f"Received image URL: {image_url}")
            # Accept URLs from hackclub CDN or other trusted CDN domains
            valid_domains = [
                'https://cdn.hackclub.com/',
                'https://hc-cdn.hel1.your-objectstorage.com/',  # Hack Club CDN
                'https://cloud-',  # Replit CDN during dev
                'https://f000.backblazeb2.com/',  # Hackclub CDN alternate domain
                'https://files.slack.com/'  # In case Slack CDN is used
            ]
            is_valid_url = any(image_url.startswith(domain) for domain in valid_domains)
            if not is_valid_url:
                app.logger.warning(f"Invalid image URL rejected: {image_url}")
                return jsonify({'error': f'Invalid image URL: {image_url}'}), 400
            else:
                app.logger.info(f"Image URL validated successfully: {image_url}")
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin
        
        if not is_member and not is_admin_access:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Check profanity in message content (if present)
        if message_content:
            if PROFANITY_CHECK_AVAILABLE and profanity_check.predict([message_content])[0] == 1:
                return jsonify({'error': 'Message contains inappropriate content'}), 400
            if profanity.contains_profanity(message_content):
                return jsonify({'error': 'Message contains inappropriate content'}), 400
        
        # Enforce 50 message limit per club
        message_count = ClubChatMessage.query.filter_by(club_id=club_id).count()
        if message_count >= 50:
            # Delete the oldest message to make room
            oldest_message = ClubChatMessage.query.filter_by(club_id=club_id)\
                .order_by(ClubChatMessage.created_at.asc())\
                .first()
            if oldest_message:
                db.session.delete(oldest_message)
        
        # Create new message
        new_message = ClubChatMessage(
            club_id=club_id,
            user_id=current_user.id,
            message=message_content if message_content else None,
            image_url=image_url if image_url else None
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        # Return the created message
        msg_dict = new_message.to_dict()
        msg_dict['can_delete'] = True  # User can always delete their own message
        msg_dict['can_edit'] = True    # User can always edit their own message
        
        return jsonify({'message': msg_dict}), 201
        
    except Exception as e:
        app.logger.error(f"Error sending chat message: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to send message'}), 500

@app.route('/api/club/<int:club_id>/chat/messages/<int:message_id>', methods=['PUT'])
@login_required
def edit_club_chat_message(club_id, message_id):
    try:
        current_user = get_current_user()
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({'error': 'Message is required'}), 400
        
        message_content = sanitize_string(data['message'].strip(), max_length=1000)
        if not message_content:
            return jsonify({'error': 'Message cannot be empty'}), 400
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin
        
        if not is_member and not is_admin_access:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get the message
        message = ClubChatMessage.query.filter_by(id=message_id, club_id=club_id).first()
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        # Only the sender can edit their message
        if message.user_id != current_user.id:
            return jsonify({'error': 'You can only edit your own messages'}), 403
        
        # Check profanity
        if PROFANITY_CHECK_AVAILABLE and profanity_check.predict([message_content])[0] == 1:
            return jsonify({'error': 'Message contains inappropriate content'}), 400
        if profanity.contains_profanity(message_content):
            return jsonify({'error': 'Message contains inappropriate content'}), 400
        
        # Update the message
        message.message = message_content
        db.session.commit()
        
        # Return the updated message
        msg_dict = message.to_dict()
        msg_dict['can_delete'] = True  # User can delete their own message
        msg_dict['can_edit'] = True    # User can edit their own message
        
        return jsonify({'message': msg_dict}), 200
        
    except Exception as e:
        app.logger.error(f"Error editing chat message: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to edit message'}), 500

@app.route('/api/club/<int:club_id>/chat/upload-image', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def upload_chat_image(club_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin
        
        if not is_member and not is_admin_access:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        data = request.get_json()
        if not data or 'image' not in data:
            return jsonify({'error': 'No image provided'}), 400
        
        base64_data = data['image']
        if not base64_data or not isinstance(base64_data, str):
            return jsonify({'error': 'Invalid image data'}), 400
            
        # Get HackClub CDN API token from environment
        cdn_token = os.getenv('HACKCLUB_CDN_TOKEN')
        if not cdn_token:
            app.logger.error("HACKCLUB_CDN_TOKEN not configured")
            return jsonify({'error': 'Image upload service not configured'}), 500
        
        try:
            # Parse base64 data URL
            if not base64_data.startswith('data:image/'):
                return jsonify({'error': 'Invalid image format'}), 400
                
            # Extract MIME type and base64 data
            header, data_part = base64_data.split(',', 1)
            mime_type = header.split(':')[1].split(';')[0]
            
            # Validate MIME type
            allowed_mime_types = {'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'}
            if mime_type not in allowed_mime_types:
                return jsonify({'error': 'Invalid image type. Allowed: JPEG, PNG, GIF, WebP'}), 400
            
            # Decode base64 and check file size (max 10MB for chat)
            import base64
            image_data = base64.b64decode(data_part)
            max_size = 10 * 1024 * 1024  # 10MB for chat images
            if len(image_data) > max_size:
                return jsonify({'error': f'Image too large. Maximum size: 10MB'}), 400
            
            # Create temporary file for upload
            import tempfile
            import uuid
            import shutil
            ext_map = {
                'image/jpeg': '.jpg',
                'image/jpg': '.jpg', 
                'image/png': '.png',
                'image/gif': '.gif',
                'image/webp': '.webp'
            }
            file_ext = ext_map.get(mime_type, '.jpg')
            
            with tempfile.NamedTemporaryFile(suffix=file_ext, delete=False) as temp_file:
                temp_file.write(image_data)
                temp_file_path = temp_file.name
            
            # Create public URL for the temp file that CDN can access
            temp_filename = f"chat_{uuid.uuid4()}{file_ext}"
            temp_upload_dir = os.path.join(app.root_path, 'static', 'temp')
            os.makedirs(temp_upload_dir, exist_ok=True)
            temp_public_path = os.path.join(temp_upload_dir, temp_filename)
            
            # Copy temp file to public location
            shutil.copy2(temp_file_path, temp_public_path)
            os.unlink(temp_file_path)  # Remove original temp file
            
            # Create public URL for CDN to access
            temp_url = f"{request.url_root}static/temp/{temp_filename}"
            
            app.logger.info(f"Prepared chat image for CDN upload: {temp_filename} ({len(image_data)} bytes)")
            
        except Exception as e:
            app.logger.error(f"Error processing chat image: {str(e)}")
            return jsonify({'error': 'Failed to process image'}), 500
        
        # Upload to HackClub CDN
        try:
            import requests
            cdn_response = requests.post(
                'https://cdn.hackclub.com/api/v3/new',
                headers={
                    'Authorization': f'Bearer {cdn_token}',
                    'Content-Type': 'application/json'
                },
                json=[temp_url],  # Single image upload
                timeout=30
            )
            
            if cdn_response.status_code != 200:
                app.logger.error(f"CDN upload failed: {cdn_response.status_code} - {cdn_response.text}")
                return jsonify({'error': 'Failed to upload image'}), 500
            
            cdn_data = cdn_response.json()
            
            if 'files' in cdn_data and len(cdn_data['files']) > 0:
                uploaded_url = cdn_data['files'][0]['deployedUrl']
                app.logger.info(f"CDN returned URL: {uploaded_url}")
                
                # Clean up temporary file
                try:
                    if os.path.exists(temp_public_path):
                        os.unlink(temp_public_path)
                except Exception as e:
                    app.logger.error(f"Error cleaning up temp file: {str(e)}")
                
                app.logger.info(f"Returning successful upload response with URL: {uploaded_url}")
                return jsonify({
                    'success': True, 
                    'image_url': uploaded_url
                }), 200
            else:
                app.logger.error(f"Unexpected CDN response format: {cdn_data}")
                return jsonify({'error': 'Failed to process upload response'}), 500
            
        except requests.RequestException as e:
            app.logger.error(f"Error uploading to CDN: {str(e)}")
            return jsonify({'error': 'Failed to connect to image service'}), 500
        
        finally:
            # Always clean up temporary files
            try:
                if os.path.exists(temp_public_path):
                    os.unlink(temp_public_path)
            except Exception as e:
                app.logger.error(f"Error cleaning up temp file in finally: {str(e)}")
                
    except Exception as e:
        app.logger.error(f"Error uploading chat image: {str(e)}")
        return jsonify({'error': 'Failed to upload image'}), 500

@app.route('/api/club/<int:club_id>/chat/messages/<int:message_id>', methods=['DELETE'])
@login_required
def delete_club_chat_message(club_id, message_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin
        
        if not is_member and not is_admin_access:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get the message
        message = ClubChatMessage.query.filter_by(id=message_id, club_id=club_id).first()
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        # Check permissions to delete
        can_delete = (
            message.user_id == current_user.id or  # Own message
            club.leader_id == current_user.id or  # Leader can delete all
            is_user_co_leader(club, current_user) or  # Co-leader can delete all
            is_admin_access  # Admin can delete all
        )
        
        if not can_delete:
            return jsonify({'error': 'You do not have permission to delete this message'}), 403
        
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        app.logger.error(f"Error deleting chat message: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete message'}), 500

# Attendance Management API Routes
@app.route('/api/clubs/<int:club_id>/attendance/sessions', methods=['GET'])
@login_required
def get_attendance_sessions(club_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        
        if not is_member:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get sessions for the club
        sessions = AttendanceSession.query.filter_by(club_id=club_id).order_by(AttendanceSession.session_date.desc()).all()
        
        return jsonify({
            'success': True,
            'sessions': [session.to_dict() for session in sessions]
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error fetching attendance sessions: {str(e)}")
        return jsonify({'error': 'Failed to fetch sessions'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions', methods=['POST'])
@login_required
def create_attendance_session(club_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can create sessions'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['title', 'session_date']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Parse date
        from datetime import datetime
        try:
            session_date = datetime.strptime(data['session_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
        
        # Parse times if provided
        start_time = None
        end_time = None
        if data.get('start_time'):
            try:
                start_time = datetime.strptime(data['start_time'], '%H:%M').time()
            except ValueError:
                return jsonify({'error': 'Invalid start time format. Use HH:MM'}), 400
        
        if data.get('end_time'):
            try:
                end_time = datetime.strptime(data['end_time'], '%H:%M').time()
            except ValueError:
                return jsonify({'error': 'Invalid end time format. Use HH:MM'}), 400
        
        # Handle max_attendance - convert empty string to None
        max_attendance = data.get('max_attendance')
        if max_attendance == '' or max_attendance is None:
            max_attendance = None
        else:
            try:
                max_attendance = int(max_attendance)
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid max_attendance value. Must be a number or empty.'}), 400

        # Create session
        session = AttendanceSession(
            club_id=club_id,
            title=data['title'],
            description=data.get('description'),
            session_date=session_date,
            start_time=start_time,
            end_time=end_time,
            location=data.get('location'),
            session_type=data.get('session_type', 'meeting'),
            max_attendance=max_attendance,
            created_by=current_user.id
        )
        
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session': session.to_dict()
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error creating attendance session: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create session'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>', methods=['GET'])
@login_required
def get_attendance_session(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        
        if not is_member:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        return jsonify({
            'success': True,
            'session': session.to_dict()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error fetching attendance session: {str(e)}")
        return jsonify({'error': 'Failed to fetch session'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/members', methods=['POST'])
@login_required
def add_member_to_session(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can manage attendance'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        data = request.get_json()
        if not data or 'user_id' not in data:
            return jsonify({'error': 'User ID is required'}), 400
        
        user_id = data['user_id']
        status = data.get('status', 'present')
        
        # Verify user is a member of the club
        member = User.query.get(user_id)
        if not member:
            return jsonify({'error': 'User not found'}), 404
        
        is_club_member = (club.leader_id == user_id or 
                         is_user_co_leader(club, User.query.get(user_id)) or
                         ClubMembership.query.filter_by(user_id=user_id, club_id=club_id).first())
        
        if not is_club_member:
            return jsonify({'error': 'User is not a member of this club'}), 400
        
        # Check if attendance record already exists
        existing_record = AttendanceRecord.query.filter_by(session_id=session_id, user_id=user_id).first()
        if existing_record:
            return jsonify({'error': 'User is already marked for attendance'}), 400
        
        # Create attendance record
        attendance_record = AttendanceRecord(
            session_id=session_id,
            user_id=user_id,
            status=status,
            check_in_time=datetime.now(timezone.utc) if status == 'present' else None,
            marked_by=current_user.id
        )
        
        db.session.add(attendance_record)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'attendance': attendance_record.to_dict()
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error adding member to session: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to add member to session'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/attendance', methods=['GET'])
@login_required
def get_session_attendance(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        
        if not is_member:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        # Get attendance records
        attendance_records = AttendanceRecord.query.filter_by(session_id=session_id).all()
        
        return jsonify({
            'success': True,
            'attendance': [record.to_dict() for record in attendance_records]
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error fetching session attendance: {str(e)}")
        return jsonify({'error': 'Failed to fetch attendance'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/guests', methods=['GET'])
@login_required
def get_session_guests(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        
        if not is_member:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        # Get guests
        guests = AttendanceGuest.query.filter_by(session_id=session_id).all()
        
        return jsonify({
            'success': True,
            'guests': [guest.to_dict() for guest in guests]
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error fetching session guests: {str(e)}")
        return jsonify({'error': 'Failed to fetch guests'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/guests', methods=['POST'])
@login_required
def add_guest_to_session(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can add guests'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Guest name is required'}), 400
        
        # Create guest record
        guest = AttendanceGuest(
            session_id=session_id,
            name=data['name'],
            email=data.get('email'),
            phone=data.get('phone'),
            organization=data.get('organization'),
            notes=data.get('notes'),
            check_in_time=datetime.now(timezone.utc),
            added_by=current_user.id
        )
        
        db.session.add(guest)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'guest': guest.to_dict()
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error adding guest to session: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to add guest'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/records/<int:record_id>', methods=['PUT'])
@login_required
def update_attendance_record(club_id, record_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can update attendance'}), 403
        
        # Get attendance record
        record = AttendanceRecord.query.get(record_id)
        if not record or record.session.club_id != club_id:
            return jsonify({'error': 'Attendance record not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'status' in data:
            record.status = data['status']
            if data['status'] == 'present' and not record.check_in_time:
                record.check_in_time = datetime.now(timezone.utc)
        
        if 'notes' in data:
            record.notes = data['notes']
        
        record.marked_by = current_user.id
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'attendance': record.to_dict()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error updating attendance record: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update attendance'}), 500

@app.route('/api/clubs/<int:club_id>/members', methods=['GET'])
@login_required
def get_club_members_api(club_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a member of the club
        club = Club.query.get_or_404(club_id)
        is_member = (club.leader_id == current_user.id or 
                    is_user_co_leader(club, current_user) or
                    ClubMembership.query.filter_by(user_id=current_user.id, club_id=club_id).first())
        
        if not is_member:
            return jsonify({'error': 'You are not a member of this club'}), 403
        
        # Get all members
        members = []
        
        # Add leader
        if club.leader:
            members.append({
                'id': club.leader.id,
                'username': club.leader.username,
                'email': club.leader.email,
                'role': 'leader'
            })
        
        # Add co-leader
        if club.co_leader:
            members.append({
                'id': club.co_leader.id,
                'username': club.co_leader.username,
                'email': club.co_leader.email,
                'role': 'co_leader'
            })
        
        # Add regular members
        memberships = ClubMembership.query.filter_by(club_id=club_id).all()
        for membership in memberships:
            members.append({
                'id': membership.user.id,
                'username': membership.user.username,
                'email': membership.user.email,
                'role': 'member'
            })
        
        return jsonify({
            'success': True,
            'members': members
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error fetching club members: {str(e)}")
        return jsonify({'error': 'Failed to fetch members'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/reports', methods=['GET'])
@login_required
def get_attendance_reports(club_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can view reports'}), 403
        
        # Parse query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        report_type = request.args.get('type', 'summary')  # summary, member_detail, session_detail
        
        # Get sessions in date range
        query = AttendanceSession.query.filter_by(club_id=club_id)
        
        if start_date:
            try:
                start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                query = query.filter(AttendanceSession.session_date >= start_date_obj)
            except ValueError:
                return jsonify({'error': 'Invalid start_date format. Use YYYY-MM-DD'}), 400
        
        if end_date:
            try:
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                query = query.filter(AttendanceSession.session_date <= end_date_obj)
            except ValueError:
                return jsonify({'error': 'Invalid end_date format. Use YYYY-MM-DD'}), 400
        
        sessions = query.order_by(AttendanceSession.session_date.desc()).all()
        
        if report_type == 'summary':
            # Generate summary report
            total_sessions = len(sessions)
            total_attendance = sum(session.get_attendance_count() for session in sessions)
            total_guests = sum(session.get_guest_count() for session in sessions)
            
            # Get member attendance statistics
            member_stats = {}
            for session in sessions:
                for record in session.attendances:
                    member_id = record.user_id
                    if member_id not in member_stats:
                        member_stats[member_id] = {
                            'username': record.user.username,
                            'email': record.user.email,
                            'total_sessions': 0,
                            'present': 0,
                            'late': 0,
                            'absent': 0,
                            'excused': 0
                        }
                    
                    member_stats[member_id]['total_sessions'] += 1
                    member_stats[member_id][record.status] += 1
            
            # Calculate attendance rate for each member
            for member_id in member_stats:
                stats = member_stats[member_id]
                attended = stats['present'] + stats['late']
                stats['attendance_rate'] = round((attended / stats['total_sessions']) * 100, 1) if stats['total_sessions'] > 0 else 0
            
            # Session type breakdown
            session_types = {}
            for session in sessions:
                session_type = session.session_type
                if session_type not in session_types:
                    session_types[session_type] = 0
                session_types[session_type] += 1
            
            report_data = {
                'summary': {
                    'total_sessions': total_sessions,
                    'total_attendance': total_attendance,
                    'total_guests': total_guests,
                    'average_attendance': round(total_attendance / total_sessions, 1) if total_sessions > 0 else 0,
                    'date_range': {
                        'start': sessions[-1].session_date.isoformat() if sessions else None,
                        'end': sessions[0].session_date.isoformat() if sessions else None
                    }
                },
                'member_stats': list(member_stats.values()),
                'session_types': session_types,
                'recent_sessions': [session.to_dict() for session in sessions[:5]]
            }
            
        elif report_type == 'member_detail':
            # Detailed member attendance report
            member_id = request.args.get('member_id')
            if not member_id:
                return jsonify({'error': 'member_id is required for member_detail report'}), 400
            
            member = User.query.get(member_id)
            if not member:
                return jsonify({'error': 'Member not found'}), 404
            
            # Get all attendance records for this member
            attendance_records = []
            for session in sessions:
                record = AttendanceRecord.query.filter_by(session_id=session.id, user_id=member_id).first()
                attendance_records.append({
                    'session': session.to_dict(),
                    'attendance': record.to_dict() if record else None
                })
            
            report_data = {
                'member': {
                    'id': member.id,
                    'username': member.username,
                    'email': member.email
                },
                'attendance_records': attendance_records
            }
            
        elif report_type == 'session_detail':
            # Detailed session report
            session_id = request.args.get('session_id')
            if not session_id:
                return jsonify({'error': 'session_id is required for session_detail report'}), 400
            
            session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
            if not session:
                return jsonify({'error': 'Session not found'}), 404
            
            attendance_records = AttendanceRecord.query.filter_by(session_id=session_id).all()
            guests = AttendanceGuest.query.filter_by(session_id=session_id).all()
            
            report_data = {
                'session': session.to_dict(),
                'attendance': [record.to_dict() for record in attendance_records],
                'guests': [guest.to_dict() for guest in guests],
                'statistics': {
                    'total_members': len(attendance_records),
                    'total_guests': len(guests),
                    'present': len([r for r in attendance_records if r.status == 'present']),
                    'late': len([r for r in attendance_records if r.status == 'late']),
                    'absent': len([r for r in attendance_records if r.status == 'absent']),
                    'excused': len([r for r in attendance_records if r.status == 'excused'])
                }
            }
        
        else:
            return jsonify({'error': 'Invalid report type'}), 400
        
        return jsonify({
            'success': True,
            'report_type': report_type,
            'data': report_data
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error generating attendance report: {str(e)}")
        return jsonify({'error': 'Failed to generate report'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/export', methods=['GET'])
@login_required
def export_attendance_data(club_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can export data'}), 403
        
        # Parse query parameters
        format_type = request.args.get('format', 'json')  # json, csv
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Get sessions in date range
        query = AttendanceSession.query.filter_by(club_id=club_id)
        
        if start_date:
            try:
                start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                query = query.filter(AttendanceSession.session_date >= start_date_obj)
            except ValueError:
                return jsonify({'error': 'Invalid start_date format. Use YYYY-MM-DD'}), 400
        
        if end_date:
            try:
                end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                query = query.filter(AttendanceSession.session_date <= end_date_obj)
            except ValueError:
                return jsonify({'error': 'Invalid end_date format. Use YYYY-MM-DD'}), 400
        
        sessions = query.order_by(AttendanceSession.session_date.desc()).all()
        
        # Prepare export data
        export_data = []
        for session in sessions:
            for record in session.attendances:
                export_data.append({
                    'session_id': session.id,
                    'session_title': session.title,
                    'session_date': session.session_date.isoformat(),
                    'session_type': session.session_type,
                    'session_location': session.location or '',
                    'member_id': record.user_id,
                    'member_username': record.user.username,
                    'member_email': record.user.email,
                    'status': record.status,
                    'check_in_time': record.check_in_time.isoformat() if record.check_in_time else '',
                    'notes': record.notes or ''
                })
            
            # Add guest data
            for guest in session.guests:
                export_data.append({
                    'session_id': session.id,
                    'session_title': session.title,
                    'session_date': session.session_date.isoformat(),
                    'session_type': session.session_type,
                    'session_location': session.location or '',
                    'member_id': 'GUEST',
                    'member_username': guest.name,
                    'member_email': guest.email or '',
                    'status': 'present',
                    'check_in_time': guest.check_in_time.isoformat() if guest.check_in_time else '',
                    'notes': guest.notes or ''
                })
        
        if format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if export_data:
                writer = csv.DictWriter(output, fieldnames=export_data[0].keys())
                writer.writeheader()
                writer.writerows(export_data)
            
            csv_data = output.getvalue()
            output.close()
            
            response = Response(
                csv_data,
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment; filename=attendance_export_{club.name.replace(" ", "_")}_{datetime.now().strftime("%Y%m%d")}.csv'
                }
            )
            return response
        
        else:  # JSON format
            return jsonify({
                'success': True,
                'data': export_data,
                'summary': {
                    'total_records': len(export_data),
                    'total_sessions': len(sessions),
                    'club_name': club.name,
                    'export_date': datetime.now().isoformat()
                }
            }), 200
        
    except Exception as e:
        app.logger.error(f"Error exporting attendance data: {str(e)}")
        return jsonify({'error': 'Failed to export data'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/records/<int:record_id>', methods=['DELETE'])
@login_required
def delete_attendance_record(club_id, record_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can delete attendance records'}), 403
        
        # Get attendance record
        record = AttendanceRecord.query.get(record_id)
        if not record or record.session.club_id != club_id:
            return jsonify({'error': 'Attendance record not found'}), 404
        
        db.session.delete(record)
        db.session.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        app.logger.error(f"Error deleting attendance record: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete attendance record'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/guests/<int:guest_id>', methods=['PUT'])
@login_required
def update_guest(club_id, guest_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can update guests'}), 403
        
        # Get guest
        guest = AttendanceGuest.query.get(guest_id)
        if not guest or guest.session.club_id != club_id:
            return jsonify({'error': 'Guest not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'name' in data:
            guest.name = data['name']
        if 'email' in data:
            guest.email = data['email']
        if 'phone' in data:
            guest.phone = data['phone']
        if 'organization' in data:
            guest.organization = data['organization']
        if 'notes' in data:
            guest.notes = data['notes']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'guest': guest.to_dict()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error updating guest: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update guest'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/guests/<int:guest_id>', methods=['DELETE'])
@login_required
def delete_guest(club_id, guest_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can delete guests'}), 403
        
        # Get guest
        guest = AttendanceGuest.query.get(guest_id)
        if not guest or guest.session.club_id != club_id:
            return jsonify({'error': 'Guest not found'}), 404
        
        db.session.delete(guest)
        db.session.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        app.logger.error(f"Error deleting guest: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete guest'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>', methods=['PUT'])
@login_required
def update_attendance_session(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can update sessions'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'title' in data:
            session.title = data['title']
        if 'description' in data:
            session.description = data['description']
        if 'session_date' in data:
            try:
                session.session_date = datetime.strptime(data['session_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
        if 'start_time' in data:
            if data['start_time']:
                try:
                    session.start_time = datetime.strptime(data['start_time'], '%H:%M').time()
                except ValueError:
                    return jsonify({'error': 'Invalid start time format. Use HH:MM'}), 400
            else:
                session.start_time = None
        if 'end_time' in data:
            if data['end_time']:
                try:
                    session.end_time = datetime.strptime(data['end_time'], '%H:%M').time()
                except ValueError:
                    return jsonify({'error': 'Invalid end time format. Use HH:MM'}), 400
            else:
                session.end_time = None
        if 'location' in data:
            session.location = data['location']
        if 'session_type' in data:
            session.session_type = data['session_type']
        if 'max_attendance' in data:
            max_attendance = data['max_attendance']
            if max_attendance == '' or max_attendance is None:
                session.max_attendance = None
            else:
                try:
                    session.max_attendance = int(max_attendance)
                except (ValueError, TypeError):
                    return jsonify({'error': 'Invalid max_attendance value. Must be a number or empty.'}), 400
        if 'is_active' in data:
            session.is_active = bool(data['is_active'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session': session.to_dict()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error updating session: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update session'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def delete_attendance_session(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can delete sessions'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        db.session.delete(session)
        db.session.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        app.logger.error(f"Error deleting session: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete session'}), 500

@app.route('/api/clubs/<int:club_id>/attendance/sessions/<int:session_id>/notes', methods=['PUT'])
@login_required
def update_session_notes(club_id, session_id):
    try:
        current_user = get_current_user()
        
        # Verify user is a leader of the club
        club = Club.query.get_or_404(club_id)
        if club.leader_id != current_user.id and not is_user_co_leader(club, current_user):
            return jsonify({'error': 'Only club leaders can update session notes'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(id=session_id, club_id=club_id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        data = request.get_json()
        if not data or 'notes' not in data:
            return jsonify({'error': 'Notes are required'}), 400
        
        # Update session description with the notes
        session.description = data['notes']
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session': session.to_dict()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error updating session notes: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update session notes'}), 500


@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/setup-hackatime')
@login_required
def setup_hackatime():
    current_user = get_current_user()
    return render_template('setup_hackatime.html', current_user=current_user)

# Blog Routes
@app.route('/blog')
@limiter.limit("100 per hour")
def blog_list():
    page = request.args.get('page', 1, type=int)
    category_slug = request.args.get('category')
    
    query = BlogPost.query.filter_by(status='published')
    
    if category_slug:
        category = BlogCategory.query.filter_by(slug=category_slug).first()
        if category:
            query = query.filter_by(category_id=category.id)
    
    posts = query.order_by(BlogPost.published_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    categories = BlogCategory.query.filter_by(is_active=True).all()
    featured_posts = BlogPost.query.filter_by(status='published', is_featured=True).order_by(BlogPost.published_at.desc()).limit(3).all()
    
    return render_template('blog_list.html', 
                         posts=posts, 
                         categories=categories,
                         featured_posts=featured_posts,
                         current_category=category_slug)

@app.route('/blog/<slug>')
@limiter.limit("200 per hour")
def blog_detail(slug):
    post = BlogPost.query.filter_by(slug=slug, status='published').first_or_404()
    
    # Get related posts from same category
    related_posts = BlogPost.query.filter_by(
        category_id=post.category_id,
        status='published'
    ).filter(BlogPost.id != post.id).limit(3).all()
    
    return render_template('blog_detail.html', post=post, related_posts=related_posts)

@app.route('/blog/create')
@login_required
@limiter.limit("10 per hour")
def blog_create():
    current_user = get_current_user()
    
    if not current_user.is_admin and not current_user.is_reviewer:
        abort(403)
    
    categories = BlogCategory.query.filter_by(is_active=True).all()
    
    return render_template('blog_create.html', categories=categories)

@app.route('/blog/create', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def blog_create_post():
    current_user = get_current_user()
    
    if not current_user.is_admin and not current_user.is_reviewer:
        abort(403)
    
    title = sanitize_string(request.form.get('title', ''), max_length=200)
    content = request.form.get('content', '').strip()  # Don't sanitize markdown content
    summary = sanitize_string(request.form.get('summary', ''), max_length=500)
    category_id = request.form.get('category_id', type=int)
    tags = request.form.get('tags', '')
    status = request.form.get('status', 'draft')
    is_featured = request.form.get('is_featured') == 'on'
    banner_image = request.form.get('banner_image', '').strip()
    
    if not title or not content:
        flash('Title and content are required', 'error')
        return redirect(url_for('blog_create'))
    
    # Generate slug from title
    slug = re.sub(r'[^\w\s-]', '', title.lower())
    slug = re.sub(r'[-\s]+', '-', slug)
    
    # Ensure slug is unique
    original_slug = slug
    counter = 1
    while BlogPost.query.filter_by(slug=slug).first():
        slug = f"{original_slug}-{counter}"
        counter += 1
    
    # Create blog post
    post = BlogPost(
        title=title,
        slug=slug,
        content=content,
        summary=summary,
        author_id=current_user.id,
        category_id=category_id if category_id else None,
        status=status,
        is_featured=is_featured,
        banner_image=banner_image if banner_image else None,
        published_at=datetime.now(timezone.utc) if status == 'published' else None
    )
    
    # Handle tags
    if tags:
        tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()]
        post.set_tags(tag_list)
    
    db.session.add(post)
    db.session.commit()
    
    flash('Blog post created successfully!', 'success')
    return redirect(url_for('blog_detail', slug=post.slug))

@app.route('/blog/<slug>/edit')
@login_required
@limiter.limit("10 per hour")
def blog_edit(slug):
    current_user = get_current_user()
    post = BlogPost.query.filter_by(slug=slug).first_or_404()
    
    if not current_user.is_admin and not current_user.is_reviewer and post.author_id != current_user.id:
        abort(403)
    
    categories = BlogCategory.query.filter_by(is_active=True).all()
    
    return render_template('blog_edit.html', 
                         post=post, 
                         categories=categories)

@app.route('/blog/<slug>/edit', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def blog_edit_post(slug):
    current_user = get_current_user()
    post = BlogPost.query.filter_by(slug=slug).first_or_404()
    
    if not current_user.is_admin and not current_user.is_reviewer and post.author_id != current_user.id:
        abort(403)
    
    title = sanitize_string(request.form.get('title', ''), max_length=200)
    content = request.form.get('content', '').strip()  # Don't sanitize markdown content
    summary = sanitize_string(request.form.get('summary', ''), max_length=500)
    category_id = request.form.get('category_id', type=int)
    tags = request.form.get('tags', '')
    status = request.form.get('status', 'draft')
    is_featured = request.form.get('is_featured') == 'on'
    banner_image = request.form.get('banner_image', '').strip()
    
    if not title or not content:
        flash('Title and content are required', 'error')
        return redirect(url_for('blog_edit', slug=slug))
    
    # Update post
    post.title = title
    post.content = content
    post.summary = summary
    post.category_id = category_id if category_id else None
    post.status = status
    post.is_featured = is_featured
    post.banner_image = banner_image if banner_image else None
    
    # Set published_at if status changed to published
    if status == 'published' and not post.published_at:
        post.published_at = datetime.now(timezone.utc)
    
    # Handle tags
    if tags:
        tag_list = [tag.strip() for tag in tags.split(',') if tag.strip()]
        post.set_tags(tag_list)
    else:
        post.set_tags([])
    
    db.session.commit()
    
    flash('Blog post updated successfully!', 'success')
    return redirect(url_for('blog_detail', slug=post.slug))

@app.route('/blog/<slug>/delete', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def blog_delete(slug):
    current_user = get_current_user()
    post = BlogPost.query.filter_by(slug=slug).first_or_404()
    
    # Only admins can delete blog posts
    if not current_user.is_admin:
        abort(403)
    
    post_title = post.title
    
    # Delete the blog post (cascading will handle club mentions)
    db.session.delete(post)
    db.session.commit()
    
    flash(f'Blog post "{post_title}" has been deleted.', 'success')
    return redirect(url_for('blog_list'))

# API Routes
@api_route('/api/clubs/<int:club_id>/join-code', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def generate_club_join_code(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)

    if not is_leader and not is_co_leader:
        return jsonify({'error': 'Only leaders and co-leaders can generate join codes'}), 403

    club.generate_join_code()
    db.session.commit()

    return jsonify({'join_code': club.join_code})

@api_route('/api/clubs/<int:club_id>/posts', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_posts(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin

    if not is_leader and not is_co_leader and not is_member and not is_admin_access:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Give admins leader privileges
    if is_admin_access:
        is_leader = True

    if request.method == 'POST':
        # Only leaders and co-leaders can create posts
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can create posts'}), 403
            
        data = request.get_json()
        content = data.get('content')

        if not content:
            return jsonify({'error': 'Content is required'}), 400

        # Security validation with auto-suspend
        valid, result = validate_input_with_security(content, "club_post", current_user, max_length=5000)
        if not valid:
            return jsonify({'error': result}), 403

        # For leaders, content is treated as markdown and converted to HTML
        if is_leader or is_co_leader:
            # Store raw markdown content (basic sanitization only)
            markdown_content = sanitize_string(result, max_length=5000, allow_html=False)
            # Convert markdown to safe HTML
            html_content = markdown_to_html(markdown_content)
        else:
            # For regular members, treat as plain text
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

        # Create audit log for post creation
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
            # Handle content_html field safely (might be NULL for some posts)
            content_html = post.content_html
            if not content_html:
                # For posts without HTML content, escape and convert newlines
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
            app.logger.error(f"Error processing post {post.id}: {str(e)}")
            # Skip problematic posts but continue processing others
            continue

    return jsonify({'posts': posts_data})

@api_route('/api/user/update', methods=['PUT'])
@login_required
@limiter.limit("5 per hour")  # More restrictive for profile updates
def update_user():
    current_user = get_current_user()
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    birthday = data.get('birthday')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    hackatime_api_key = data.get('hackatime_api_key')
    show_alias = data.get('show_alias')
    hide_email = data.get('hide_email')

    # Validate username
    if username and username != current_user.username:
        valid, result = validate_username(username)
        if not valid:
            return jsonify({'error': result}), 400

        existing_user = User.query.filter_by(username=result).first()
        if existing_user:
            return jsonify({'error': 'Username already taken'}), 400
        current_user.username = result

    # Validate email
    if email and email != current_user.email:
        valid, result = validate_email(email)
        if not valid:
            return jsonify({'error': result}), 400

        existing_user = User.query.filter_by(email=result).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 400
        current_user.email = result
    # Update privacy settings
    if show_alias is not None:
        current_user.show_alias = bool(show_alias)
    if hide_email is not None:
        current_user.hide_email = bool(hide_email)

    # Validate names
    if first_name is not None:
        valid, result = validate_name(first_name, "First name")
        if not valid:
            return jsonify({'error': result}), 400
        current_user.first_name = result if result.strip() else None

    if last_name is not None:
        valid, result = validate_name(last_name, "Last name")
        if not valid:
            return jsonify({'error': result}), 400
        current_user.last_name = result if result.strip() else None

    if birthday is not None:
        current_user.birthday = datetime.strptime(birthday, '%Y-%m-%d').date() if birthday else None

    if hackatime_api_key is not None:
        # Sanitize API key
        api_key = sanitize_string(hackatime_api_key, max_length=255)
        current_user.hackatime_api_key = api_key if api_key.strip() else None


    if new_password:
        if not current_password:
            return jsonify({'error': 'Current password required to change password'}), 400
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Validate new password strength
        valid, result = validate_password(new_password)
        if not valid:
            return jsonify({'error': result}), 400
            
        current_user.set_password(new_password)

    db.session.commit()
    return jsonify({'message': 'Account updated successfully'})

# Admin routes (simplified)
@app.route('/admin')
@admin_required
def admin_dashboard():
    current_user = get_current_user()

    # Check if mobile device
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'

    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()
    
    # Calculate total club balance across all clubs
    total_club_balance = db.session.query(db.func.sum(Club.balance)).scalar() or 0

    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_clubs = Club.query.order_by(Club.created_at.desc()).limit(5).all()
    recent_posts = ClubPost.query.order_by(ClubPost.created_at.desc()).limit(10).all()

    # Get user permissions for UI access control
    user_permissions = current_user.get_all_permissions()
    can_manage_roles = current_user.has_permission('system.manage_roles')
    can_manage_users = current_user.has_permission('users.assign_roles')

    # Tab-specific permissions
    can_view_users = current_user.has_permission('users.view') or current_user.is_admin
    can_view_clubs = current_user.has_permission('clubs.view') or current_user.is_admin
    can_view_content = current_user.has_permission('content.view') or current_user.is_admin
    can_manage_settings = current_user.has_permission('system.manage_settings') or current_user.is_admin
    can_access_api = current_user.has_permission('admin.access_dashboard') or current_user.is_admin

    # Use mobile template if mobile device
    if (is_mobile or force_mobile) and not force_desktop:
        return render_template('admin_dashboard_mobile.html',
                             total_users=total_users,
                             total_clubs=total_clubs,
                             total_posts=total_posts,
                             total_assignments=total_assignments,
                             total_club_balance=total_club_balance,
                             recent_users=recent_users,
                             recent_clubs=recent_clubs,
                             recent_posts=recent_posts,
                             user_permissions=user_permissions,
                             can_manage_roles=can_manage_roles,
                             can_manage_users=can_manage_users,
                             can_view_users=can_view_users,
                             can_view_clubs=can_view_clubs,
                             can_view_content=can_view_content,
                             can_manage_settings=can_manage_settings,
                             can_access_api=can_access_api)

    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_clubs=total_clubs,
                         total_posts=total_posts,
                         total_assignments=total_assignments,
                         total_club_balance=total_club_balance,
                         recent_users=recent_users,
                         recent_clubs=recent_clubs,
                         recent_posts=recent_posts,
                         user_permissions=user_permissions,
                         can_manage_roles=can_manage_roles,
                         can_manage_users=can_manage_users,
                         can_view_users=can_view_users,
                         can_view_clubs=can_view_clubs,
                         can_view_content=can_view_content,
                         can_manage_settings=can_manage_settings,
                         can_access_api=can_access_api)

@app.route('/admin/projects/review')
@reviewer_required
def project_review():
    """Reviewer page for reviewing YSWS project submissions"""
    current_user = get_current_user()
    return render_template('project_review.html', current_user=current_user)

@api_route('/api/projects/review', methods=['GET'])
@reviewer_required
@limiter.limit("100 per hour")
def api_get_project_submissions():
    """Get all YSWS project submissions for review"""
    try:
        submissions = airtable_service.get_ysws_project_submissions()
        return jsonify({
            'success': True,
            'projects': submissions
        })
    except Exception as e:
        app.logger.error(f"Error fetching project submissions: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch project submissions'
        }), 500

@api_route('/api/projects/review/<string:project_id>', methods=['PUT'])
@reviewer_required
@limiter.limit("50 per hour")
def api_update_project_review(project_id):
    """Update the review status of a YSWS project submission"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        new_status = data.get('status')
        decision_reason = data.get('decisionReason')
        
        if not new_status or not decision_reason:
            return jsonify({'error': 'Status and decision reason are required'}), 400

        # Validate status
        valid_statuses = ['Pending', 'Approved', 'Rejected', 'Flagged']
        if new_status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400

        # Get current user for transactions
        current_user = get_current_user()
        
        # Get current status before updating to check for revocations
        current_submission = None
        current_status = None
        try:
            submissions = airtable_service.get_ysws_project_submissions()
            current_submission = next((s for s in submissions if s['id'] == project_id), None)
            current_status = current_submission.get('status') if current_submission else None
        except Exception as e:
            app.logger.warning(f"Could not fetch current submission status: {str(e)}")
        
        # Prepare update fields (no grant amount in regular review)
        update_fields = {
            'Status': new_status,
            'Decision Reason': decision_reason
        }

        # Update in Airtable
        success = airtable_service.update_ysws_project_submission(project_id, update_fields)
        
        if success:
            # If approving, add grant amount to club balance
            if new_status == 'Approved':
                try:
                    # Get the project submission details
                    submissions = airtable_service.get_ysws_project_submissions()
                    submission = next((s for s in submissions if s['id'] == project_id), None)
                    
                    if submission:
                        submitter_email = submission.get('email')
                        grant_amount_raw = submission.get('grantAmount')  # This already prioritizes override amount
                        
                        if submitter_email and grant_amount_raw:
                            # Parse grant amount (uses override if available, otherwise calculated amount)
                            try:
                                grant_amount_str = str(grant_amount_raw).strip()
                                # Remove currency symbols and common formatting
                                import re
                                grant_amount_str = re.sub(r'[^\d.-]', '', grant_amount_str)
                                
                                if grant_amount_str:
                                    from decimal import Decimal
                                    grant_amount = Decimal(grant_amount_str)
                                    
                                    if grant_amount > 0:
                                        # Find the user and their club
                                        submitter = User.query.filter_by(email=submitter_email).first()
                                        if submitter:
                                            # Check if user leads a club or is a member of one
                                            club = None
                                            if submitter.led_clubs:
                                                club = submitter.led_clubs[0]
                                            elif submitter.club_memberships:
                                                club = submitter.club_memberships[0].club
                                            
                                            if club:
                                                # Create transaction record for the grant (this will update balance automatically)
                                                try:
                                                    success, tx_result = create_club_transaction(
                                                        club_id=club.id,
                                                        transaction_type='grant',
                                                        amount=int(grant_amount * 100),  # Convert dollars to tokens
                                                        description=f"Project grant approved for project {project_id}",
                                                        reference_id=project_id,
                                                        reference_type='project_grant',
                                                        created_by=current_user.id
                                                    )
                                                    
                                                    if success:
                                                        app.logger.info(f"Transaction recorded for project grant: {int(grant_amount * 100)} tokens credited")
                                                        
                                                        # Add 100 tokens to piggy bank for approved project
                                                        try:
                                                            club.piggy_bank_tokens = (club.piggy_bank_tokens or 0) + 100
                                                            db.session.commit()
                                                            app.logger.info(f"Added 100 tokens to piggy bank for club '{club.name}' (ID: {club.id}) - Total piggy bank: {club.piggy_bank_tokens}")
                                                            
                                                            # Create piggy bank transaction record
                                                            try:
                                                                success, tx_result = create_club_transaction(
                                                                    club_id=club.id,
                                                                    transaction_type='piggy_bank_credit',
                                                                    amount=100,
                                                                    description=f"Piggy bank credit for approved project {project_id}",
                                                                    reference_id=project_id,
                                                                    reference_type='piggy_bank_grant',
                                                                    created_by=current_user.id
                                                                )
                                                                if success:
                                                                    app.logger.info(f"Piggy bank transaction recorded: 100 tokens credited")
                                                            except Exception as piggy_tx_error:
                                                                app.logger.error(f"Failed to record piggy bank transaction: {str(piggy_tx_error)}")
                                                        except Exception as piggy_error:
                                                            db.session.rollback()
                                                            app.logger.error(f"Failed to add tokens to piggy bank: {str(piggy_error)}")
                                                    else:
                                                        app.logger.error(f"Failed to record transaction for project grant: {tx_result}")
                                                except Exception as tx_error:
                                                    app.logger.error(f"Exception while recording project grant transaction: {str(tx_error)}")
                                                
                                                app.logger.info(f"Added ${grant_amount} to club '{club.name}' (ID: {club.id}) for approved project {project_id}")
                                                
                                                # Log the project submission for leaderboard tracking
                                                try:
                                                    project_submission = ProjectSubmission(
                                                        user_id=submitter.id,
                                                        club_id=club.id,
                                                        project_name=submission.get('hackatimeProject', 'Unknown Project'),
                                                        project_url=submission.get('codeUrl') or submission.get('playableUrl'),
                                                        approved_at=datetime.now(timezone.utc),
                                                        approved_by=current_user.id
                                                    )
                                                    db.session.add(project_submission)
                                                    db.session.commit()
                                                    
                                                    # Update quest progress for member projects
                                                    update_quest_progress(club.id, 'member_projects', 1)
                                                    
                                                    app.logger.info(f"Logged project submission for user {submitter.username} in club {club.name}")
                                                except Exception as proj_log_error:
                                                    app.logger.error(f"Failed to log project submission: {str(proj_log_error)}")
                                                    db.session.rollback()
                                            else:
                                                app.logger.warning(f"User {submitter_email} is not associated with any club")
                                        else:
                                            app.logger.warning(f"Submitter {submitter_email} not found in system")
                            except (ValueError, TypeError) as e:
                                app.logger.error(f"Error parsing grant amount '{grant_amount_raw}': {str(e)}")
                        else:
                            app.logger.warning(f"Missing email or grant amount for project {project_id}")
                    else:
                        app.logger.warning(f"Project submission {project_id} not found")
                except Exception as e:
                    app.logger.error(f"Error adding grant amount to club balance: {str(e)}")
            
            # If revoking approval (was approved, now not approved), deduct from balance and piggy bank
            elif current_status == 'Approved' and new_status != 'Approved':
                try:
                    if current_submission:
                        submitter_email = current_submission.get('email')
                        grant_amount_raw = current_submission.get('grantAmount')
                        
                        if submitter_email and grant_amount_raw:
                            # Parse grant amount to deduct
                            try:
                                grant_amount_str = str(grant_amount_raw).strip()
                                import re
                                grant_amount_str = re.sub(r'[^\d.-]', '', grant_amount_str)
                                
                                if grant_amount_str:
                                    from decimal import Decimal
                                    grant_amount = Decimal(grant_amount_str)
                                    
                                    if grant_amount > 0:
                                        # Find the user and their club
                                        submitter = User.query.filter_by(email=submitter_email).first()
                                        if submitter:
                                            club = None
                                            if submitter.led_clubs:
                                                club = submitter.led_clubs[0]
                                            elif submitter.club_memberships:
                                                club = submitter.club_memberships[0].club
                                            
                                            if club:
                                                # Create transaction record to deduct the grant
                                                try:
                                                    success, tx_result = create_club_transaction(
                                                        club_id=club.id,
                                                        transaction_type='debit',
                                                        amount=-int(grant_amount * 100),  # Negative for deduction
                                                        description=f"Project grant revoked for project {project_id} (status changed to {new_status})",
                                                        reference_id=project_id,
                                                        reference_type='project_grant_revocation',
                                                        created_by=current_user.id
                                                    )
                                                    
                                                    if success:
                                                        app.logger.info(f"Transaction recorded for project grant revocation: {int(grant_amount * 100)} tokens deducted")
                                                        
                                                        # Deduct 100 tokens from piggy bank for revoked project
                                                        try:
                                                            if club.piggy_bank_tokens >= 100:
                                                                club.piggy_bank_tokens -= 100
                                                                db.session.commit()
                                                                app.logger.info(f"Deducted 100 tokens from piggy bank for club '{club.name}' (ID: {club.id}) - Total piggy bank: {club.piggy_bank_tokens}")
                                                                
                                                                # Create piggy bank transaction record
                                                                try:
                                                                    success, tx_result = create_club_transaction(
                                                                        club_id=club.id,
                                                                        transaction_type='piggy_bank_debit',
                                                                        amount=-100,
                                                                        description=f"Piggy bank deduction for revoked project {project_id}",
                                                                        reference_id=project_id,
                                                                        reference_type='piggy_bank_revocation',
                                                                        created_by=current_user.id
                                                                    )
                                                                    if success:
                                                                        app.logger.info(f"Piggy bank transaction recorded: 100 tokens deducted")
                                                                except Exception as piggy_tx_error:
                                                                    app.logger.error(f"Failed to record piggy bank transaction: {str(piggy_tx_error)}")
                                                            else:
                                                                app.logger.warning(f"Club '{club.name}' has insufficient piggy bank tokens ({club.piggy_bank_tokens}) to deduct 100 tokens")
                                                        except Exception as piggy_error:
                                                            db.session.rollback()
                                                            app.logger.error(f"Failed to deduct tokens from piggy bank: {str(piggy_error)}")
                                                    else:
                                                        app.logger.error(f"Failed to record transaction for project grant revocation: {tx_result}")
                                                except Exception as tx_error:
                                                    app.logger.error(f"Exception while recording project grant revocation transaction: {str(tx_error)}")
                                                
                                                app.logger.info(f"Revoked ${grant_amount} from club '{club.name}' (ID: {club.id}) for project {project_id} status change")
                            except (ValueError, TypeError) as e:
                                app.logger.error(f"Error parsing grant amount for revocation '{grant_amount_raw}': {str(e)}")
                except Exception as e:
                    app.logger.error(f"Error revoking grant amount from club balance: {str(e)}")
            
            # Log the review action
            app.logger.info(f"{('Admin' if current_user.is_admin else 'Reviewer')} {current_user.username} updated project {project_id}: status={new_status}")
            
            # Create comprehensive audit log with separate transaction
            try:
                # Use a separate session for audit logging to avoid transaction conflicts
                from sqlalchemy import create_engine
                from sqlalchemy.orm import sessionmaker
                
                engine = db.get_engine()
                SessionLocal = sessionmaker(bind=engine)
                audit_session = SessionLocal()
                
                try:
                    log_entry = AuditLog(
                        user_id=current_user.id,
                        action_type='project_review',
                        action_category='project',
                        target_type='project_submission',
                        target_id=project_id,
                        description=f"{('Admin' if current_user.is_admin else 'Reviewer')} {current_user.username} reviewed project submission: {new_status}",
                        details=json.dumps({
                            'status': new_status,
                            'decision_reason': decision_reason,
                            'reviewer_role': 'admin' if current_user.is_admin else 'reviewer',
                            'club_balance_updated': new_status == 'Approved'
                        }),
                        ip_address=get_real_ip(),
                        user_agent=request.headers.get('User-Agent'),
                        severity='info',
                        admin_action=current_user.is_admin
                    )
                    
                    audit_session.add(log_entry)
                    audit_session.commit()
                    
                    app.logger.info(f"Audit log created successfully for project review: {log_entry.id}")
                    
                except Exception as audit_error:
                    audit_session.rollback()
                    app.logger.error(f"Failed to create audit log in separate session: {str(audit_error)}")
                finally:
                    audit_session.close()
                    
            except Exception as e:
                app.logger.error(f"Exception setting up audit log session: {str(e)}")
            
            return jsonify({
                'success': True,
                'message': 'Project review updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to update project in Airtable'
            }), 500

    except Exception as e:
        app.logger.error(f"Error updating project review: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@api_route('/api/projects/grant-override/<string:project_id>', methods=['PUT'])
@admin_required
@limiter.limit("30 per hour")
def api_grant_override(project_id):
    """Override the grant amount for a YSWS project submission"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        grant_amount = data.get('grantAmount')
        override_reason = data.get('overrideReason')
        
        if grant_amount is None or not override_reason:
            return jsonify({'error': 'Grant amount and override reason are required'}), 400

        # Validate grant amount
        try:
            grant_amount = float(grant_amount)
            if grant_amount < 0:
                return jsonify({'error': 'Grant amount must be non-negative'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid grant amount format'}), 400

        # Prepare update fields for grant override
        update_fields = {
            'Grant Amount Override': grant_amount,
            'Grant Override Reason': override_reason
        }

        # Update in Airtable
        success = airtable_service.update_ysws_project_submission(project_id, update_fields)
        
        if success:
            # Log the grant override action
            current_user = get_current_user()
            app.logger.info(f"Admin {current_user.username} overrode grant amount for project {project_id}: ${grant_amount} - {override_reason}")
            
            # Create comprehensive audit log
            create_audit_log(
                action_type='grant_override',
                description=f"Admin {current_user.username} overrode grant amount for project submission",
                user=current_user,
                target_type='project_submission',
                target_id=project_id,
                details={
                    'new_grant_amount': float(grant_amount),
                    'override_reason': override_reason,
                    'formatted_amount': f"${grant_amount:.2f}"
                },
                severity='warning',
                admin_action=True,
                category='admin'
            )
            
            return jsonify({
                'success': True,
                'message': f'Grant amount overridden to {int(grant_amount * 100)} tokens'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to update grant amount in Airtable'
            }), 500

    except Exception as e:
        app.logger.error(f"Error applying grant override: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@api_route('/api/projects/delete/<string:project_id>', methods=['DELETE'])
@admin_required
@limiter.limit("20 per hour")
def api_delete_project(project_id):
    """Delete a YSWS project submission"""
    try:
        # Delete from Airtable
        success = airtable_service.delete_ysws_project_submission(project_id)
        
        if success:
            # Log the deletion action
            current_user = get_current_user()
            app.logger.info(f"Admin {current_user.username} deleted project submission {project_id}")
            
            # Create comprehensive audit log
            create_audit_log(
                action_type='project_delete',
                description=f"Admin {current_user.username} permanently deleted project submission",
                user=current_user,
                target_type='project_submission',
                target_id=project_id,
                details={
                    'action': 'permanent_deletion',
                    'warning': 'This action cannot be undone'
                },
                severity='critical',
                admin_action=True,
                category='admin'
            )
            
            return jsonify({
                'success': True,
                'message': 'Project submission deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to delete project from Airtable'
            }), 500

    except Exception as e:
        app.logger.error(f"Error deleting project: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

# Order Review Routes
@app.route('/admin/orders/review')
@permission_required('orders.view')
def order_review():
    """Reviewer page for reviewing shop orders"""
    current_user = get_current_user()
    return render_template('admin_order_review.html', current_user=current_user)

@api_route('/api/admin/orders', methods=['GET'])
@permission_required('orders.view')
@limiter.limit("100 per hour")
def api_get_all_orders():
    """Get all orders for review"""
    try:
        orders = airtable_service.get_all_orders()
        return jsonify({'orders': orders})
    except Exception as e:
        app.logger.error(f"Error fetching orders for review: {str(e)}")
        return jsonify({'error': 'Failed to fetch orders'}), 500

@api_route('/api/admin/orders/<string:order_id>/status', methods=['PATCH'])
@permission_required('orders.approve')
@limiter.limit("50 per hour")
def api_update_order_status(order_id):
    """Update order status and reviewer reason - automatically refunds if rejected"""
    try:
        current_user = get_current_user()
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        status = data.get('status')
        reviewer_reason = data.get('reviewer_reason', '')

        if not status:
            return jsonify({'error': 'Status is required'}), 400

        if status not in ['Pending', 'Shipped', 'Flagged', 'Rejected Shipment']:
            return jsonify({'error': 'Invalid status'}), 400

        # CRITICAL: If rejecting an order, automatically process refund
        refund_processed = False
        refund_message = ''

        if status == 'Rejected Shipment':
            # Get order details to process refund
            all_orders = airtable_service.get_all_orders()
            order_details = None
            for order in all_orders:
                if order['id'] == order_id:
                    order_details = order
                    break

            if order_details:
                club_name = order_details.get('club_name')
                refund_amount = order_details.get('total_estimated_cost', 0)

                if club_name and refund_amount > 0:
                    # Find the club to refund
                    club = Club.query.filter_by(name=club_name).first()
                    if club:
                        # Check if this order has already been refunded
                        existing_refund = ClubTransaction.query.filter_by(
                            club_id=club.id,
                            transaction_type='refund',
                            reference_id=order_id,
                            reference_type='order_refund'
                        ).first()

                        if not existing_refund:
                            # Process refund
                            success, tx_result = create_club_transaction(
                                club_id=club.id,
                                transaction_type='refund',
                                amount=int(refund_amount * 100),  # Convert to tokens (positive for credit)
                                description=f"Refund for rejected order: {order_details.get('products', 'N/A')}. Reason: {reviewer_reason}",
                                reference_id=order_id,
                                reference_type='order_refund',
                                created_by=current_user.id
                            )

                            if success:
                                refund_processed = True
                                refund_message = f' Refund of {int(refund_amount * 100)} tokens processed automatically.'
                                app.logger.info(f"Auto-refund processed for order {order_id}: {int(refund_amount * 100)} tokens to club {club.name}")
                            else:
                                app.logger.error(f"Failed to process auto-refund for order {order_id}: {tx_result}")
                                refund_message = ' WARNING: Refund failed - manual intervention required.'
                        else:
                            refund_message = ' (Order was already refunded previously)'

        # Update status in Airtable
        result = airtable_service.update_order_status(order_id, status, reviewer_reason)

        if result:
            # Log the review action
            app.logger.info(f"{'Admin' if current_user.is_admin else 'Reviewer'} {current_user.username} updated order {order_id} status to {status}")

            return jsonify({
                'success': True,
                'message': f'Order status updated to {status}.{refund_message}',
                'refund_processed': refund_processed
            })
        else:
            return jsonify({'error': 'Failed to update order status'}), 500

    except Exception as e:
        app.logger.error(f"Error updating order status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/admin/orders/<string:order_id>', methods=['DELETE'])
@admin_required
@limiter.limit("50 per hour")
def api_delete_order(order_id):
    """Delete an order record (admin only)"""
    try:
        current_user = get_current_user()
        
        # Delete from Airtable
        result = airtable_service.delete_order(order_id)
        
        if result:
            # Log the delete action
            app.logger.warning(f"Admin {current_user.username} deleted order {order_id}")
            
            return jsonify({
                'success': True,
                'message': 'Order deleted successfully'
            })
        else:
            return jsonify({'error': 'Failed to delete order'}), 500
    
    except Exception as e:
        app.logger.error(f"Error deleting order: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/admin/orders/<string:order_id>/refund', methods=['POST'])
@admin_required
@limiter.limit("20 per hour")
def api_refund_order(order_id):
    """Refund a shipped order and mark as rejected"""
    try:
        current_user = get_current_user()
        
        # Get all orders to find this specific one
        all_orders = airtable_service.get_all_orders()
        order_details = None
        for order in all_orders:
            if order['id'] == order_id:
                order_details = order
                break
        
        if not order_details:
            return jsonify({'error': 'Order not found'}), 404
        
        # Check if order is shipped or pending
        if order_details.get('shipment_status') not in ['Shipped', 'Pending']:
            return jsonify({'error': 'Can only refund shipped or pending orders'}), 400
        
        # Get the club to refund the balance
        club_name = order_details.get('club_name')
        refund_amount = order_details.get('total_estimated_cost', 0)
        
        if club_name and refund_amount > 0:
            # Find the club and add refund to balance
            club = Club.query.filter_by(name=club_name).first()
            if club:
                # Check if this order has already been refunded
                existing_refund = ClubTransaction.query.filter_by(
                    club_id=club.id,
                    transaction_type='refund',
                    reference_id=order_id,
                    reference_type='order_refund'
                ).first()
                
                if existing_refund:
                    return jsonify({'error': 'Order has already been refunded'}), 400
                
                # Create transaction record for the refund (this will update balance automatically)
                try:
                    success, tx_result = create_club_transaction(
                        club_id=club.id,
                        transaction_type='refund',
                        amount=int(refund_amount * 100),  # Convert to tokens (positive for credit)
                        description=f"Order refund for order {order_id}",
                        reference_id=order_id,
                        reference_type='order_refund',
                        created_by=current_user.id
                    )
                    
                    if success:
                        app.logger.info(f"Transaction recorded for refund: {int(refund_amount * 100)} tokens credited")
                    else:
                        app.logger.error(f"Failed to record transaction for refund: {tx_result}")
                except Exception as tx_error:
                    app.logger.error(f"Exception while recording refund transaction: {str(tx_error)}")
                
                app.logger.info(f"Refunded {int(refund_amount * 100)} tokens to club '{club_name}' balance (now {club.tokens} tokens)")
        
        # Update order status to rejected with refund note
        result = airtable_service.update_order_status(
            order_id, 
            'Rejected Shipment', 
            f"REFUNDED ${refund_amount} - Order refunded by admin {current_user.username}"
        )
        
        if result:
            # Log the refund action
            app.logger.warning(f"Admin {current_user.username} refunded order {order_id} - ${refund_amount} credited to {club_name}")
            
            return jsonify({
                'success': True,
                'message': f'Order refunded ({int(refund_amount * 100)} tokens credited to club balance) and marked as rejected'
            })
        else:
            return jsonify({'error': 'Failed to process refund'}), 500
    
    except Exception as e:
        app.logger.error(f"Error refunding order {order_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@api_route('/api/admin/users/by-ip', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_users_by_ip():
    """Get all users who have used a specific IP address"""
    ip_address = request.args.get('ip')
    if not ip_address:
        return jsonify({'error': 'IP address parameter required'}), 400
    
    # Find users by registration IP or last login IP
    users_by_reg_ip = User.query.filter_by(registration_ip=ip_address).all()
    users_by_login_ip = User.query.filter_by(last_login_ip=ip_address).all()
    
    # Find users by IP in their history (search in JSON field)
    users_by_history = User.query.filter(User.all_ips.contains(f'"{ip_address}"')).all()
    
    # Combine and deduplicate
    all_users = list({user.id: user for user in users_by_reg_ip + users_by_login_ip + users_by_history}.values())
    
    users_data = []
    for user in all_users:
        user_ips = user.get_all_ips()
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'registration_ip': user.registration_ip,
            'last_login_ip': user.last_login_ip,
            'all_ips': user_ips,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'is_admin': user.is_admin,
            'is_reviewer': user.is_reviewer,
            'is_suspended': user.is_suspended
        })
    
    return jsonify({
        'ip_address': ip_address,
        'users': users_data,
        'total_users': len(users_data)
    })

@api_route('/api/admin/users/<int:user_id>/ips', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_user_ips(user_id):
    """Get all IP addresses used by a specific user"""
    user = User.query.get_or_404(user_id)
    
    user_ips = user.get_all_ips()
    
    return jsonify({
        'user_id': user_id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_admin': user.is_admin,
        'is_reviewer': user.is_reviewer,
        'is_suspended': user.is_suspended,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'registration_ip': user.registration_ip,
        'last_login_ip': user.last_login_ip,
        'all_ips': user_ips,
        'total_ips': len(user_ips)
    })

@api_route('/api/clubs/<int:club_id>/assignments', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_assignments(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin

    if not is_leader and not is_co_leader and not is_member and not is_admin_access:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Give admins leader privileges
    if is_admin_access:
        is_leader = True

    if request.method == 'POST':
        is_leader = club.leader_id == current_user.id
        is_co_leader = is_user_co_leader(club, current_user)
        
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can create assignments'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        due_date = data.get('due_date')
        for_all_members = data.get('for_all_members', True)

        if not title or not description:
            return jsonify({'error': 'Title and description are required'}), 400

        # Security validation with auto-suspend for title
        valid, result = validate_input_with_security(title, "assignment_title", current_user, max_length=200)
        if not valid:
            return jsonify({'error': result}), 403
        title = sanitize_string(result, max_length=200)
        
        # Security validation with auto-suspend for description
        valid, result = validate_input_with_security(description, "assignment_description", current_user, max_length=5000)
        if not valid:
            return jsonify({'error': result}), 403
        description = sanitize_string(result, max_length=5000)

        if not title.strip() or not description.strip():
            return jsonify({'error': 'Title and description cannot be empty'}), 400

        assignment = ClubAssignment(
            club_id=club_id,
            title=title,
            description=description,
            due_date=datetime.fromisoformat(due_date) if due_date else None,
            for_all_members=for_all_members
        )
        db.session.add(assignment)
        db.session.commit()

        # Create audit log for assignment creation
        create_audit_log(
            action_type='assignment_create',
            description=f"User {current_user.username} created assignment '{title}' in club '{club.name}'",
            user=current_user,
            target_type='club',
            target_id=str(club_id),
            details={
                'assignment_title': title,
                'club_name': club.name,
                'due_date': due_date,
                'for_all_members': for_all_members
            },
            severity='info',
            admin_action=False,
            category='club'
        )

        return jsonify({'message': 'Assignment created successfully'})

    assignments = ClubAssignment.query.filter_by(club_id=club_id).order_by(ClubAssignment.created_at.desc()).all()
    assignments_data = [{
        'id': assignment.id,
        'title': assignment.title,
        'description': assignment.description,
        'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
        'for_all_members': assignment.for_all_members,
        'status': assignment.status,
        'created_at': assignment.created_at.isoformat()
    } for assignment in assignments]

    return jsonify({'assignments': assignments_data})

@api_route('/api/clubs/<int:club_id>/meetings', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_meetings(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    is_admin_access = request.args.get('admin') == 'true' and current_user.is_admin

    if not is_leader and not is_co_leader and not is_member and not is_admin_access:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Give admins leader privileges
    if is_admin_access:
        is_leader = True

    if request.method == 'POST':
        is_leader = club.leader_id == current_user.id
        is_co_leader = is_user_co_leader(club, current_user)
        
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can schedule meetings'}), 403

        data = request.get_json()
        title = data.get('title')
        description = data.get('description')
        meeting_date = data.get('meeting_date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        location = data.get('location')
        meeting_link = data.get('meeting_link')

        if not title or not meeting_date or not start_time:
            return jsonify({'error': 'Title, date, and start time are required'}), 400

        # Security validation with auto-suspend for meeting fields
        text_fields = ['title', 'description', 'location', 'meeting_link']
        for field in text_fields:
            if field in data and data[field]:
                valid, result = validate_input_with_security(data[field], f"meeting_{field}", current_user)
                if not valid:
                    return jsonify({'error': result}), 403
                data[field] = sanitize_string(result)

        meeting = ClubMeeting(
            club_id=club_id,
            title=data.get('title'),
            description=data.get('description'),
            meeting_date=datetime.strptime(meeting_date, '%Y-%m-%d').date(),
            start_time=start_time,
            end_time=end_time,
            location=data.get('location'),
            meeting_link=data.get('meeting_link')
        )
        db.session.add(meeting)
        db.session.commit()

        return jsonify({'message': 'Meeting scheduled successfully'})

    meetings = ClubMeeting.query.filter_by(club_id=club_id).order_by(ClubMeeting.meeting_date.desc()).all()
    meetings_data = [{
        'id': meeting.id,
        'title': meeting.title,
        'description': meeting.description,
        'meeting_date': meeting.meeting_date.isoformat(),
        'start_time': meeting.start_time,
        'end_time': meeting.end_time,
        'location': meeting.location,
        'meeting_link': meeting.meeting_link,
        'created_at': meeting.created_at.isoformat()
    } for meeting in meetings]

    return jsonify({'meetings': meetings_data})

@api_route('/api/clubs/<int:club_id>/meetings/<int:meeting_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_meeting_detail(club_id, meeting_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    meeting = ClubMeeting.query.get_or_404(meeting_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can manage meetings'}), 403

    if meeting.club_id != club_id:
        return jsonify({'error': 'Meeting does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(meeting)
        db.session.commit()
        return jsonify({'message': 'Meeting deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        meeting.title = data.get('title', meeting.title)
        meeting.description = data.get('description', meeting.description)
        if data.get('meeting_date'):
            meeting.meeting_date = datetime.strptime(data['meeting_date'], '%Y-%m-%d').date()
        meeting.start_time = data.get('start_time', meeting.start_time)
        meeting.end_time = data.get('end_time', meeting.end_time)
        meeting.location = data.get('location', meeting.location)
        meeting.meeting_link = data.get('meeting_link', meeting.meeting_link)

        db.session.commit()
        return jsonify({'message': 'Meeting updated successfully'})

@api_route('/api/clubs/<int:club_id>/project-submission', methods=['POST'])
@login_required
@economy_required
@limiter.limit("10 per hour")
def submit_project(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Check if user is leader, co-leader, or member of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    
    # Validate required fields with security checks
    required_fields = ['first_name', 'last_name', 'email', 'project_name', 'project_description', 'github_url', 'live_url']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Security validation for text fields
    text_fields = ['first_name', 'last_name', 'project_name', 'project_description', 'github_url', 'live_url', 'github_username']
    for field in text_fields:
        if field in data and data[field]:
            valid, result = validate_input_with_security(data[field], f"project_{field}", current_user)
            if not valid:
                return jsonify({'error': result}), 403
            data[field] = result

    # Get submitter info based on member selection (for leaders) or current user
    member_id = data.get('member_id')
    
    # Only leaders and co-leaders can submit for others
    if member_id and member_id != str(current_user.id):
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'You can only submit projects for yourself'}), 403
        
        # Verify the selected member is actually in the club
        selected_user = User.query.get(member_id)
        if not selected_user:
            return jsonify({'error': 'Selected member not found'}), 404
        
        # Check if selected user is leader, co-leader, or member
        selected_is_leader = club.leader_id == selected_user.id
        selected_is_co_leader = club.co_leader_id == selected_user.id if club.co_leader_id else False
        selected_is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=selected_user.id).first()
        
        if not selected_is_leader and not selected_is_co_leader and not selected_is_member:
            return jsonify({'error': 'Selected user is not a member of this club'}), 403

    # Security check for hours manipulation
    if data.get('suspend_user'):
        log_security_event(
            'HOURS_MANIPULATION', 
            data.get('suspension_reason', 'Hours manipulation detected'),
            current_user.id
        )
        
        # Suspend the user using existing system
        current_user.is_suspended = True
        db.session.commit()
        
        return jsonify({
            'error': 'Account suspended for security violation. Contact support if you believe this is an error.',
            'suspended': True
        }), 403

    # Count club members (leader + co-leader + memberships)
    member_count = 1  # Leader
    if club.co_leader_id:
        member_count += 1  # Co-leader
    member_count += len(club.members)  # Regular members
    
    # Check member count requirement (can be overridden by admin)
    admin_override = data.get('admin_override', False)
    if member_count < 3 and not (current_user.is_admin and admin_override):
        return jsonify({
            'error': f'Your club must have at least 3 members to submit projects. Current members: {member_count}',
            'member_count': member_count,
            'is_admin': current_user.is_admin
        }), 400

    # Prepare submission data for Airtable
    submission_data = {
        'first_name': data.get('first_name'),
        'last_name': data.get('last_name'),
        'email': data.get('email'),
        'age': data.get('age', ''),
        'birthday': data.get('birthday', ''),
        'project_name': data.get('project_name'),
        'project_description': data.get('project_description'),
        'github_url': data.get('github_url'),
        'github_username': data.get('github_username', ''),
        'live_url': data.get('live_url'),
        'address_1': data.get('address_1', ''),
        'address_2': data.get('address_2', ''),
        'city': data.get('city', ''),
        'state': data.get('state', ''),
        'zip': data.get('zip', ''),
        'country': data.get('country', ''),
        'project_hours': data.get('project_hours', '0'),
        'doing_well': data.get('doing_well', ''),
        'improve': data.get('improve', ''),
        'club_name': club.name,
        'leader_email': club.leader.email,
        'is_in_person_meeting': True,  # Default to true for project submissions
        'club_member_count': member_count
    }

    app.logger.info(f"Project submission for club {club.name}: {submission_data.get('project_name')}")

    # Log the submission for tracking
    app.logger.info(f"Project submission by user {current_user.id} for club {club_id}: {submission_data}")
    
    # Create audit log for project submission
    create_audit_log(
        action_type='project_submission',
        description=f"User {current_user.username} submitted project '{submission_data.get('project_name')}' for club {club.name}",
        user=current_user,
        target_type='club',
        target_id=club_id,
        details={
            'club_name': club.name,
            'project_name': submission_data.get('project_name'),
            'github_url': submission_data.get('github_url'),
            'submitter_email': submission_data.get('email'),
            'admin_override_used': admin_override,
            'member_count': member_count
        },
        category='club'
    )
    
    # Submit to Airtable for tracking
    try:
        app.logger.info(f"AIRTABLE: Attempting to submit project to Airtable...")
        
        # Use a simple submission method
        if hasattr(airtable_service, 'submit_project_data'):
            airtable_result = airtable_service.submit_project_data(submission_data)
            if airtable_result:
                app.logger.info(f"AIRTABLE: Successfully submitted project to Airtable: {airtable_result}")
            else:
                app.logger.error(f"AIRTABLE: Failed to submit project to Airtable")
        else:
            app.logger.warning(f"AIRTABLE: No Airtable submission method available")
    except Exception as e:
        app.logger.error(f"AIRTABLE: Exception during Airtable submission: {str(e)}")
    
    # Note: Tokens will be awarded when the project is approved through the review process
    
    return jsonify({'message': 'Project submitted successfully!'})

@api_route('/api/clubs/<int:club_id>/transactions', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_club_transactions(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user has access to view club transactions
    is_authorized, role = verify_club_leadership(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_authorized and not is_member and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
    
    # Get filter parameters
    transaction_type = request.args.get('type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Build query
    query = ClubTransaction.query.filter_by(club_id=club_id)
    
    if transaction_type:
        query = query.filter(ClubTransaction.transaction_type == transaction_type)
    
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(ClubTransaction.created_at >= start_dt)
        except ValueError:
            return jsonify({'error': 'Invalid start_date format'}), 400
    
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(ClubTransaction.created_at <= end_dt)
        except ValueError:
            return jsonify({'error': 'Invalid end_date format'}), 400
    
    # Execute paginated query
    transactions_pagination = query.order_by(ClubTransaction.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    transactions_data = [transaction.to_dict() for transaction in transactions_pagination.items]
    
    return jsonify({
        'transactions': transactions_data,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': transactions_pagination.total,
            'pages': transactions_pagination.pages,
            'has_next': transactions_pagination.has_next,
            'has_prev': transactions_pagination.has_prev
        },
        'club': {
            'id': club.id,
            'name': club.name,
            'current_balance': club.tokens
        }
    })

@api_route('/api/clubs/<int:club_id>/piggy-bank/transactions', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_club_piggy_bank_transactions(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user has access to view club transactions
    is_authorized, role = verify_club_leadership(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_authorized and not is_member and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # Max 100 per page
    
    # Get filter parameters
    transaction_type = request.args.get('type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Build query for piggy bank transactions only
    query = ClubTransaction.query.filter_by(club_id=club_id).filter(
        ClubTransaction.transaction_type.in_(['piggy_bank_credit', 'piggy_bank_debit'])
    )
    
    if transaction_type:
        query = query.filter(ClubTransaction.transaction_type == transaction_type)
    
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(ClubTransaction.created_at >= start_dt)
        except ValueError:
            return jsonify({'error': 'Invalid start_date format'}), 400
    
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(ClubTransaction.created_at <= end_dt)
        except ValueError:
            return jsonify({'error': 'Invalid end_date format'}), 400
    
    # Order by most recent first
    query = query.order_by(ClubTransaction.created_at.desc())
    
    # Paginate
    transactions_pagination = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    transactions_data = []
    for transaction in transactions_pagination.items:
        transactions_data.append(transaction.to_dict())
    
    return jsonify({
        'transactions': transactions_data,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': transactions_pagination.total,
            'pages': transactions_pagination.pages,
            'has_next': transactions_pagination.has_next,
            'has_prev': transactions_pagination.has_prev
        },
        'club': {
            'id': club.id,
            'name': club.name,
            'piggy_bank_balance': club.piggy_bank_tokens or 0
        }
    })

@api_route('/api/admin/clubs/<int:club_id>/transactions', methods=['POST'])
@admin_required
@limiter.limit("50 per hour")
def admin_create_club_transaction(club_id):
    current_user = get_current_user()
    
    club = Club.query.get_or_404(club_id)
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['transaction_type', 'amount', 'description']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Validate transaction type
    valid_types = ['credit', 'debit', 'grant', 'refund', 'manual']
    if data['transaction_type'] not in valid_types:
        return jsonify({'error': f'Invalid transaction type. Must be one of: {valid_types}'}), 400
    
    # Validate amount
    try:
        amount = int(data['amount'])
    except (ValueError, TypeError):
        return jsonify({'error': 'Amount must be an integer'}), 400
    
    # For debit transactions, make amount negative
    if data['transaction_type'] == 'debit' and amount > 0:
        amount = -amount
    
    # Create the transaction
    success, result = create_club_transaction(
        club_id=club_id,
        transaction_type=data['transaction_type'],
        amount=amount,
        description=data['description'],
        user_id=data.get('user_id'),
        reference_id=data.get('reference_id'),
        reference_type=data.get('reference_type', 'admin_action'),
        created_by=current_user.id
    )
    
    if not success:
        return jsonify({'error': f'Failed to create transaction: {result}'}), 500
    
    # Create audit log for admin transaction
    create_audit_log(
        action_type='admin_club_transaction',
        description=f"Admin {current_user.username} created {data['transaction_type']} transaction for club {club.name}: {amount} tokens - {data['description']}",
        user=current_user,
        target_type='club',
        target_id=club_id,
        details={
            'transaction_type': data['transaction_type'],
            'amount': amount,
            'description': data['description'],
            'club_name': club.name,
            'balance_after': result.balance_after
        },
        category='admin'
    )
    
    return jsonify({
        'message': 'Transaction created successfully',
        'transaction': result.to_dict(),
        'club_balance': club.tokens
    })

@api_route('/api/clubs/<int:club_id>/pizza-grants', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_pizza_grants(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        data = request.get_json()
        
        # Basic validation
        required_fields = ['member_id', 'project_name', 'first_name', 'last_name', 'email', 
                          'project_description', 'github_url', 'live_url', 'is_in_person_meeting']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate new requirements
        is_in_person = data.get('is_in_person_meeting', False)
        if not is_in_person:
            return jsonify({'error': 'Project submissions must be from in-person meetings only. Virtual meetings are not eligible for grants.'}), 400
        
        # Count club members (leader + co-leader + memberships)
        member_count = 1  # Leader
        if club.co_leader_id:
            member_count += 1  # Co-leader
        member_count += len(club.members)  # Regular members
        
        if member_count < 3:
            return jsonify({'error': f'Your club must have at least 3 members to submit for grants. Current members: {member_count}'}), 400

        # Submit to Airtable
        submission_data = {
            'project_name': data.get('project_name'),
            'first_name': data.get('first_name'),
            'last_name': data.get('last_name'),
            'email': data.get('email'),
            'birthday': data.get('birthday'),
            'age': data.get('age', ''),
            'project_description': data.get('project_description'),
            'github_url': data.get('github_url'),
            'github_username': data.get('github_username', ''),
            'live_url': data.get('live_url'),
            'learning': data.get('learning'),
            'doing_well': data.get('doing_well'),
            'improve': data.get('improve'),
            'address_1': data.get('address_1'),
            'address_2': data.get('address_2'),
            'city': data.get('city'),
            'state': data.get('state'),
            'zip': data.get('zip'),
            'country': data.get('country'),
            'screenshot_url': data.get('screenshot_url'),
            'project_hours': data.get('project_hours', '0'),
            'club_name': club.name,
            'leader_email': club.leader.email,
            'is_in_person_meeting': is_in_person,
            'club_member_count': member_count
        }

        app.logger.info(f"Pizza grant submission data: project_name={submission_data.get('project_name')}")
        app.logger.info(f"Screenshot URL received: {submission_data.get('screenshot_url')}")
        app.logger.info(f"Full submission data keys: {list(submission_data.keys())}")

        # Log to Airtable
        airtable_result = airtable_service.log_pizza_grant(submission_data)
        
        if airtable_result:
            # Clean up uploaded screenshot file after successful submission
            screenshot_url = submission_data.get('screenshot_url')
            if screenshot_url and 'static/uploads/' in screenshot_url:
                try:
                    # Extract filename from URL
                    filename = screenshot_url.split('static/uploads/')[-1]
                    file_path = os.path.join(app.root_path, 'static', 'uploads', filename)
                    
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        app.logger.info(f"Cleaned up uploaded file: {file_path}")
                except Exception as e:
                    app.logger.warning(f"Failed to clean up uploaded file: {str(e)}")
            
            return jsonify({'message': 'Project submission successful!'})
        else:
            return jsonify({'error': 'Failed to submit to grants system'}), 500

    # GET request - return submissions for this club
    try:
        submissions = airtable_service.get_pizza_grant_submissions()
        # Filter submissions for this club
        club_submissions = [s for s in submissions if s.get('club_name', '').lower() == club.name.lower()]
        return jsonify({'submissions': club_submissions})
    except Exception as e:
        app.logger.error(f"Error fetching submissions: {str(e)}")
        return jsonify({'submissions': []})

@api_route('/api/clubs/<int:club_id>/projects', methods=['GET'])
@login_required
@limiter.limit("500 per hour")
def club_projects(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    projects = ClubProject.query.filter_by(club_id=club_id).order_by(ClubProject.updated_at.desc()).all()
    projects_data = [{
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'url': project.url,
        'github_url': project.github_url,
        'featured': project.featured,
        'created_at': project.created_at.isoformat(),
        'updated_at': project.updated_at.isoformat(),
        'owner': {
            'id': project.user.id,
            'username': project.user.username
        }
    } for project in projects]

    return jsonify({'projects': projects_data})

@api_route('/api/clubs/<int:club_id>/resources', methods=['GET', 'POST'])
@login_required
@limiter.limit("500 per hour")
def club_resources(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        is_leader = club.leader_id == current_user.id
        is_co_leader = is_user_co_leader(club, current_user)
        
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can add resources'}), 403

        data = request.get_json()
        title = data.get('title')
        url = data.get('url')
        description = data.get('description')
        icon = data.get('icon', 'book')

        if not title or not url:
            return jsonify({'error': 'Title and URL are required'}), 400

        # Security validation with auto-suspend for resource fields
        resource_fields = ['title', 'url', 'description', 'icon']
        for field in resource_fields:
            if field in data and data[field]:
                valid, result = validate_input_with_security(data[field], f"resource_{field}", current_user)
                if not valid:
                    return jsonify({'error': result}), 403
                data[field] = sanitize_string(result)

        resource = ClubResource(
            club_id=club_id,
            title=data.get('title'),
            url=data.get('url'),
            description=data.get('description'),
            icon=data.get('icon', 'book')
        )
        db.session.add(resource)
        db.session.commit()

        return jsonify({'message': 'Resource added successfully'})

    resources = ClubResource.query.filter_by(club_id=club_id).order_by(ClubResource.created_at.desc()).all()
    resources_data = [{
        'id': resource.id,
        'title': resource.title,
        'url': resource.url,
        'description': resource.description,
        'icon': resource.icon,
        'created_at': resource.created_at.isoformat()
    } for resource in resources]

    return jsonify({'resources': resources_data})

@api_route('/api/clubs/<int:club_id>/posts/<int:post_id>', methods=['DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_post_detail(club_id, post_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    post = ClubPost.query.get_or_404(post_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can delete posts'}), 403

    if post.club_id != club_id:
        return jsonify({'error': 'Post does not belong to this club'}), 404

    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post deleted successfully'})

@api_route('/api/clubs/<int:club_id>/assignments/<int:assignment_id>', methods=['DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_assignment_detail(club_id, assignment_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    assignment = ClubAssignment.query.get_or_404(assignment_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can delete assignments'}), 403

    if assignment.club_id != club_id:
        return jsonify({'error': 'Assignment does not belong to this club'}), 404

    db.session.delete(assignment)
    db.session.commit()
    return jsonify({'message': 'Assignment deleted successfully'})

@api_route('/api/clubs/<int:club_id>/resources/<int:resource_id>', methods=['PUT', 'DELETE'])
@login_required
@limiter.limit("200 per hour")
def club_resource_detail(club_id, resource_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    resource = ClubResource.query.get_or_404(resource_id)

    # Check if user is club leader or admin
    if club.leader_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Only club leaders can manage resources'}), 403

    if resource.club_id != club_id:
        return jsonify({'error': 'Resource does not belong to this club'}), 404

    if request.method == 'DELETE':
        db.session.delete(resource)
        db.session.commit()
        return jsonify({'message': 'Resource deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        resource.title = data.get('title', resource.title)
        resource.url = data.get('url', resource.url)
        resource.description = data.get('description', resource.description)
        resource.icon = data.get('icon', resource.icon)

        db.session.commit()
        return jsonify({'message': 'Resource updated successfully'})

@api_route('/api/clubs/<int:club_id>/members', methods=['GET'])
@login_required
@limiter.limit("500 per hour")
def get_club_members(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Check if user is leader, co-leader, or member of this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    members_data = []

    # Add all members from membership records (includes leaders with correct roles)
    for membership in club.members:
        members_data.append({
            'id': membership.user.id,
            'username': membership.user.username,
            'email': membership.user.email,
            'first_name': membership.user.first_name,
            'last_name': membership.user.last_name,
            'role': membership.role
        })

    # Sort by role priority (leader first, then co-leader, then members)
    role_priority = {'leader': 1, 'co-leader': 2, 'member': 3}
    members_data.sort(key=lambda x: (role_priority.get(x['role'], 4), x['username'].lower()))

    return jsonify({'members': members_data})

@api_route('/api/clubs/<int:club_id>/members/<int:user_id>', methods=['DELETE'])
@login_required
@limiter.limit("100 per hour")
def remove_club_member(club_id, user_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # Allow members to remove themselves (leave club)
    is_removing_self = (current_user.id == user_id)

    if is_removing_self:
        # Prevent leader from leaving their own club
        if user_id == club.leader_id:
            return jsonify({'error': 'Club leaders cannot leave their club. Transfer leadership first.'}), 400

        # Prevent co-leaders from leaving (they need to be demoted first)
        co_leader_membership = ClubMembership.query.filter_by(
            club_id=club_id,
            user_id=user_id,
            role='co-leader'
        ).first()
        if co_leader_membership:
            return jsonify({'error': 'Co-leaders cannot leave. Ask the leader to demote you first.'}), 400
    else:
        # STRICT AUTHORIZATION: Only leaders/co-leaders can remove OTHER members
        is_authorized, role = verify_club_leadership(club, current_user, require_leader_only=False)

        if not is_authorized:
            app.logger.warning(f"Unauthorized member removal attempt: User {current_user.id} tried to remove member {user_id} from club {club_id}")
            return jsonify({'error': 'Unauthorized: Only club leaders and co-leaders can remove members'}), 403

        # Prevent removing the main leader
        if user_id == club.leader_id:
            return jsonify({'error': 'Cannot remove club leader'}), 400

        # Prevent removing co-leader
        if hasattr(club, 'co_leader_id') and user_id == club.co_leader_id:
            return jsonify({'error': 'Cannot remove co-leader'}), 400

    # Verify the target user is actually a member
    membership = ClubMembership.query.filter_by(club_id=club_id, user_id=user_id).first()
    if not membership:
        return jsonify({'error': 'User is not a member of this club'}), 404

    try:
        db.session.delete(membership)
        db.session.commit()

        if is_removing_self:
            app.logger.info(f"Member left club: User {current_user.id} left club {club_id}")
            return jsonify({'success': True, 'message': 'You have left the club successfully'})
        else:
            app.logger.info(f"Member removed: User {current_user.id} ({role}) removed member {user_id} from club {club_id}")
            return jsonify({'success': True, 'message': 'Member removed successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error removing member: {str(e)}")
        return jsonify({'error': 'Failed to remove member'}), 500

@api_route('/api/clubs/<int:club_id>/co-leader', methods=['POST', 'DELETE'])
@login_required
@limiter.limit("50 per hour")
def make_co_leader(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # STRICT AUTHORIZATION: Only the actual leader of THIS specific club can manage co-leaders
    is_authorized, role = verify_club_leadership(club, current_user, require_leader_only=True)
    
    if not is_authorized:
        app.logger.warning(f"Unauthorized co-leader management attempt: User {current_user.id} tried to manage co-leader for club {club_id}")
        return jsonify({'error': 'Unauthorized: Only club leaders can manage co-leaders'}), 403

    data = request.get_json(silent=True) or {}
    
    # Check if this is an email verification step
    if 'step' in data and data['step'] == 'verify_email':
        verification_code = data.get('verification_code', '').strip()
        
        if not verification_code:
            return jsonify({'error': 'Verification code is required'}), 400
        
        # Verify the email code
        is_code_valid = airtable_service.verify_email_code(club.leader.email, verification_code)
        
        if is_code_valid:
            return jsonify({
                'success': True,
                'message': 'Email verification successful! You can now manage co-leaders.',
                'email_verified': True
            })
        else:
            return jsonify({'error': 'Invalid or expired verification code. Please check your email or request a new code.'}), 400
    
    # Check if this is a request to send verification code
    if 'step' in data and data['step'] == 'send_verification':
        verification_code = airtable_service.send_email_verification(club.leader.email)
        
        if verification_code:
            return jsonify({
                'success': True,
                'message': 'Verification code sent to your email. Please check your inbox.',
                'verification_sent': True
            })
        else:
            return jsonify({'error': 'Failed to send verification code. Please try again.'}), 500

    if request.method == 'DELETE':
        # Require email verification for removing co-leader
        email_verified = data.get('email_verified', False)
        if not email_verified:
            return jsonify({
                'error': 'Email verification required for this action',
                'requires_verification': True,
                'verification_email': club.leader.email
            }), 403
        
        # Remove co-leader
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400

        # Find the co-leader membership record
        membership = ClubMembership.query.filter_by(club_id=club_id, user_id=user_id, role='co-leader').first()
        if not membership:
            return jsonify({'error': 'User is not a co-leader of this club'}), 400

        try:
            # Update membership role back to member
            membership.role = 'member'

            db.session.commit()
            return jsonify({'success': True, 'message': 'Co-leader removed successfully'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to remove co-leader: {str(e)}'}), 500

    else:
        # POST method - Make user co-leader
        user_id = data.get('user_id')

        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400
        
        # Require email verification for adding co-leader
        email_verified = data.get('email_verified', False)
        if not email_verified:
            return jsonify({
                'error': 'Email verification required for this action',
                'requires_verification': True,
                'verification_email': club.leader.email
            }), 403

        # Check if user is a member of the club
        membership = ClubMembership.query.filter_by(club_id=club_id, user_id=user_id).first()
        if not membership and user_id != club.leader_id:
            return jsonify({'error': 'User is not a member of this club'}), 404

        # Check if user is already the leader
        if user_id == club.leader_id:
            return jsonify({'error': 'User is already the club leader'}), 400

        # Check if user is already a co-leader (via membership role)
        existing_co_leader_membership = ClubMembership.query.filter_by(
            club_id=club_id, user_id=user_id, role='co-leader'
        ).first()
        if existing_co_leader_membership:
            return jsonify({'error': 'User is already a co-leader'}), 400

        # Make user co-leader
        try:
            # Update membership role if user is a member
            if membership:
                membership.role = 'co-leader'
            else:
                # Create a new membership record with co-leader role
                new_membership = ClubMembership(
                    user_id=user_id,
                    club_id=club_id,
                    role='co-leader'
                )
                db.session.add(new_membership)

            db.session.commit()
            return jsonify({'success': True, 'message': 'User promoted to co-leader successfully'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to promote user: {str(e)}'}), 500


@api_route('/api/clubs/<int:club_id>/remove-co-leader', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def remove_co_leader(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # STRICT AUTHORIZATION: Only the actual leader of THIS specific club can remove co-leaders
    is_authorized, role = verify_club_leadership(club, current_user, require_leader_only=True)
    
    if not is_authorized:
        app.logger.warning(f"Unauthorized co-leader removal attempt: User {current_user.id} tried to remove co-leader from club {club_id}")
        return jsonify({'error': 'Unauthorized: Only club leaders can remove co-leaders'}), 403

    data = request.get_json(silent=True) or {}
    
    # Check if this is an email verification step
    if 'step' in data and data['step'] == 'verify_email':
        verification_code = data.get('verification_code', '').strip()
        
        if not verification_code:
            return jsonify({'error': 'Verification code is required'}), 400
        
        # Verify the email code
        is_code_valid = airtable_service.verify_email_code(club.leader.email, verification_code)
        
        if is_code_valid:
            return jsonify({
                'success': True,
                'message': 'Email verification successful! You can now remove co-leaders.',
                'email_verified': True
            })
        else:
            return jsonify({'error': 'Invalid or expired verification code. Please check your email or request a new code.'}), 400
    
    # Check if this is a request to send verification code
    if 'step' in data and data['step'] == 'send_verification':
        verification_code = airtable_service.send_email_verification(club.leader.email)
        
        if verification_code:
            return jsonify({
                'success': True,
                'message': 'Verification code sent to your email. Please check your inbox.',
                'verification_sent': True
            })
        else:
            return jsonify({'error': 'Failed to send verification code. Please try again.'}), 500

    if not hasattr(club, 'co_leader_id') or not club.co_leader_id:
        return jsonify({'error': 'Club does not have a co-leader'}), 400
    
    # Require email verification for removing co-leader
    email_verified = data.get('email_verified', False)
    if not email_verified:
        return jsonify({
            'error': 'Email verification required for this action',
            'requires_verification': True,
            'verification_email': club.leader.email
        }), 403

    try:
        co_leader_id = club.co_leader_id
        club.co_leader_id = None

        # Update membership role back to member
        membership = ClubMembership.query.filter_by(club_id=club_id, user_id=co_leader_id).first()
        if membership:
            membership.role = 'member'

        db.session.commit()
        return jsonify({'success': True, 'message': 'Co-leader removed successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to remove co-leader: {str(e)}'}), 500

@api_route('/api/clubs/<int:club_id>/settings', methods=['PUT'])
@login_required
@limiter.limit("20 per hour")  # More restrictive for settings changes
def update_club_settings(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # STRICT AUTHORIZATION: Only actual leaders/co-leaders of THIS specific club
    is_authorized, role = verify_club_leadership(club, current_user, require_leader_only=False)
    
    if not is_authorized:
        app.logger.warning(f"Unauthorized settings update attempt: User {current_user.id} tried to update settings for club {club_id}")
        return jsonify({'error': 'Unauthorized: Only club leaders and co-leaders can update settings'}), 403

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Check if this is an email verification step
    if 'step' in data and data['step'] == 'verify_email':
        verification_code = data.get('verification_code', '').strip()
        
        if not verification_code:
            return jsonify({'error': 'Verification code is required'}), 400
        
        # Verify the email code
        is_code_valid = airtable_service.verify_email_code(club.leader.email, verification_code)
        
        if is_code_valid:
            return jsonify({
                'success': True,
                'message': 'Email verification successful! You can now update settings.',
                'email_verified': True
            })
        else:
            return jsonify({'error': 'Invalid or expired verification code. Please check your email or request a new code.'}), 400
    
    # Check if this is a request to send verification code
    if 'step' in data and data['step'] == 'send_verification':
        verification_code = airtable_service.send_email_verification(club.leader.email)
        
        if verification_code:
            return jsonify({
                'success': True,
                'message': 'Verification code sent to your email. Please check your inbox.',
                'verification_sent': True
            })
        else:
            return jsonify({'error': 'Failed to send verification code. Please try again.'}), 500
    
    # For actual settings updates, require email verification for significant changes
    requires_verification = any(key in data for key in ['name', 'location', 'description'])
    
    if requires_verification:
        email_verified = data.get('email_verified', False)
        if not email_verified:
            return jsonify({
                'error': 'Email verification required for this change',
                'requires_verification': True,
                'verification_email': club.leader.email
            }), 403
    
    # Validate input lengths before processing
    if 'name' in data:
        if not data['name'] or len(data['name'].strip()) < 1:
            return jsonify({'error': 'Club name cannot be empty'}), 400
        if len(data['name']) > 100:
            return jsonify({'error': 'Club name too long (max 100 characters)'}), 400
            
        # Security validation with auto-suspend
        valid, result = validate_input_with_security(data['name'], "club_name", current_user, max_length=100)
        if not valid:
            return jsonify({'error': result}), 403
        
        filtered_name = filter_profanity_comprehensive(result)
        club.name = sanitize_string(filtered_name, max_length=100)
        
    if 'description' in data:
        if len(data['description']) > 1000:
            return jsonify({'error': 'Description too long (max 1000 characters)'}), 400
            
        # Security validation with auto-suspend
        valid, result = validate_input_with_security(data['description'], "club_description", current_user, max_length=1000)
        if not valid:
            return jsonify({'error': result}), 403
        
        filtered_description = filter_profanity_comprehensive(result)
        club.description = sanitize_string(filtered_description, max_length=1000)
        
    if 'location' in data:
        if len(data['location']) > 255:
            return jsonify({'error': 'Location too long (max 255 characters)'}), 400
            
        # Security validation with auto-suspend
        valid, result = validate_input_with_security(data['location'], "club_location", current_user, max_length=255)
        if not valid:
            return jsonify({'error': result}), 403
            
        club.location = sanitize_string(result, max_length=255)
    
    club.updated_at = datetime.now(timezone.utc)
    
    # Sync with Airtable if club has airtable_data
    airtable_data = club.get_airtable_data()
    if airtable_data and airtable_data.get('airtable_id'):
        try:
            # Update Airtable record
            airtable_record_id = airtable_data['airtable_id']
            update_url = f"{airtable_service.clubs_base_url}/{airtable_record_id}"
            
            airtable_fields = {}
            if 'name' in data:
                airtable_fields['Club Name'] = club.name
            if 'description' in data:
                airtable_fields['Description'] = club.description
            if 'location' in data:
                airtable_fields['Location'] = club.location
            
            if airtable_fields:
                payload = {'fields': airtable_fields}
                response = requests.patch(update_url, headers=airtable_service.headers, json=payload)
                
                if response.status_code == 200:
                    app.logger.info(f"Successfully synced club {club_id} changes to Airtable")
                else:
                    app.logger.warning(f"Failed to sync club {club_id} to Airtable: {response.status_code} - {response.text}")
        except Exception as e:
            app.logger.error(f"Error syncing club {club_id} to Airtable: {str(e)}")
    
    db.session.commit()
    return jsonify({'message': 'Club settings updated successfully'})

@api_route('/api/clubs/<int:club_id>/update-email', methods=['POST'])
@login_required
@limiter.limit("5 per hour")  # Restrictive for email updates
def update_club_email(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # STRICT AUTHORIZATION: Only actual leaders of THIS specific club
    if current_user.id != club.leader_id:
        app.logger.warning(f"Unauthorized email update attempt: User {current_user.id} tried to update email for club {club_id}")
        return jsonify({'error': 'Unauthorized: Only club leaders can update email'}), 403

    # Get the club's airtable data
    airtable_data = club.get_airtable_data()
    if not airtable_data or not airtable_data.get('airtable_id'):
        return jsonify({'error': 'Club is not linked to Airtable records'}), 400

    try:
        app.logger.info(f"Updating email for club {club_id} from {club.leader.email} to {current_user.email}")
        
        # Update Airtable record with new email
        airtable_record_id = airtable_data['airtable_id']
        update_url = f"{airtable_service.clubs_base_url}/{airtable_record_id}"
        
        airtable_fields = {
            "Current Leaders' Emails": current_user.email
        }
        
        payload = {'fields': airtable_fields}
        response = requests.patch(update_url, headers=airtable_service.headers, json=payload)
        
        if response.status_code == 200:
            app.logger.info(f"Successfully updated club {club_id} email in Airtable to {current_user.email}")
            return jsonify({
                'success': True,
                'message': 'Email updated successfully in Hack Club records'
            })
        else:
            app.logger.error(f"Failed to update club {club_id} email in Airtable: {response.status_code} - {response.text}")
            return jsonify({'error': 'Failed to update email in Hack Club records'}), 500
            
    except Exception as e:
        app.logger.error(f"Error updating club {club_id} email: {str(e)}")
        return jsonify({'error': 'An error occurred while updating email'}), 500

@api_route('/api/clubs/<int:club_id>/background', methods=['POST', 'PUT'])
@login_required
@limiter.limit("10 per hour")  # Reasonable limit for background uploads
def manage_club_background(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # STRICT AUTHORIZATION: Only leaders and co-leaders can manage background
    is_authorized, role = verify_club_leadership(club, current_user, require_leader_only=False)
    
    if not is_authorized:
        app.logger.warning(f"Unauthorized background management attempt: User {current_user.id} tried to manage background for club {club_id}")
        return jsonify({'error': 'Unauthorized: Only club leaders and co-leaders can manage background'}), 403
    
    if request.method == 'POST':
        # Handle background image upload
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if file_ext not in allowed_extensions:
            return jsonify({'error': 'Invalid file type. Only PNG, JPG, JPEG, GIF, and WebP files are allowed'}), 400
        
        # Read and validate image data
        try:
            file.seek(0)  # Reset file pointer
            image_data = file.read()
            
            # Check file size (max 10MB)
            if len(image_data) > 10 * 1024 * 1024:
                return jsonify({'error': 'File too large. Maximum size is 10MB'}), 400
            
            if len(image_data) < 1024:  # Min 1KB
                return jsonify({'error': 'File too small. Minimum size is 1KB'}), 400
            
            # Get CDN token
            cdn_token = os.environ.get('HACKCLUB_CDN_TOKEN')
            if not cdn_token:
                app.logger.error("HACKCLUB_CDN_TOKEN not found in environment variables")
                return jsonify({'error': 'Upload service not configured'}), 500
            
            # Create temporary file for CDN upload
            import tempfile
            import shutil
            import uuid
            
            with tempfile.NamedTemporaryFile(suffix=f'.{file_ext}', delete=False) as temp_file:
                temp_file.write(image_data)
                temp_file_path = temp_file.name
            
            # Create public URL for the temp file that CDN can access
            temp_filename = f"club_background_{club_id}_{uuid.uuid4().hex[:8]}.{file_ext}"
            temp_upload_dir = os.path.join(app.root_path, 'static', 'temp')
            os.makedirs(temp_upload_dir, exist_ok=True)
            temp_public_path = os.path.join(temp_upload_dir, temp_filename)
            
            # Copy temp file to public location
            shutil.copy2(temp_file_path, temp_public_path)
            os.unlink(temp_file_path)  # Remove original temp file
            
            # Create public URL for CDN to access
            temp_url = f"{request.url_root}static/temp/{temp_filename}"
            
            app.logger.info(f"Prepared club background image for CDN upload: {temp_filename} ({len(image_data)} bytes)")
            
        except Exception as e:
            app.logger.error(f"Error processing club background image: {str(e)}")
            return jsonify({'error': 'Failed to process image'}), 500
        
        # Upload to HackClub CDN
        try:
            import requests
            cdn_response = requests.post(
                'https://cdn.hackclub.com/api/v3/new',
                headers={
                    'Authorization': f'Bearer {cdn_token}',
                    'Content-Type': 'application/json'
                },
                json=[temp_url],  # Single image upload
                timeout=30
            )
            
            if cdn_response.status_code != 200:
                app.logger.error(f"CDN upload failed: {cdn_response.status_code} - {cdn_response.text}")
                return jsonify({'error': 'Failed to upload image to CDN'}), 500
            
            cdn_data = cdn_response.json()
            
            if 'files' in cdn_data and len(cdn_data['files']) > 0:
                uploaded_url = cdn_data['files'][0]['deployedUrl']
                app.logger.info(f"CDN returned URL for club background: {uploaded_url}")
                
                # Clean up temporary file
                try:
                    if os.path.exists(temp_public_path):
                        os.unlink(temp_public_path)
                except Exception as e:
                    app.logger.warning(f"Failed to clean up temp file {temp_public_path}: {str(e)}")
                
                # Save the background URL to the database
                try:
                    club.background_image_url = uploaded_url
                    club.updated_at = datetime.now(timezone.utc)
                    db.session.commit()
                    
                    return jsonify({
                        'success': True,
                        'background_url': uploaded_url,
                        'message': 'Background image uploaded successfully'
                    })
                    
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Error saving background URL to database: {str(e)}")
                    return jsonify({'error': 'Failed to save background image'}), 500
            else:
                app.logger.error(f"Unexpected CDN response format: {cdn_data}")
                return jsonify({'error': 'Unexpected CDN response format'}), 500
                
        except requests.RequestException as e:
            app.logger.error(f"CDN upload request failed: {str(e)}")
            return jsonify({'error': 'Failed to upload to CDN'}), 500
        except Exception as e:
            app.logger.error(f"Unexpected error during CDN upload: {str(e)}")
            return jsonify({'error': 'Upload failed'}), 500
    
    elif request.method == 'PUT':
        # Handle background settings update (blur, remove image)
        data = request.get_json(silent=True) or {}
        
        try:
            if 'blur' in data:
                blur_value = data['blur']
                if not isinstance(blur_value, (int, float)) or blur_value < 0 or blur_value > 100:
                    return jsonify({'error': 'Blur value must be between 0 and 100'}), 400
                club.background_blur = int(blur_value)
            
            if 'remove_background' in data and data['remove_background']:
                club.background_image_url = None
                club.background_blur = 0
            
            club.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'background_url': club.background_image_url,
                'background_blur': club.background_blur,
                'message': 'Background settings updated successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating background settings: {str(e)}")
            return jsonify({'error': 'Failed to update background settings'}), 500

@api_route('/api/clubs/<int:club_id>/transfer-leadership', methods=['POST'])
@login_required
@limiter.limit("10 per hour")  # Very restrictive for leadership transfers
def transfer_leadership(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    # STRICT AUTHORIZATION: Only the actual leader of THIS specific club can transfer leadership
    is_authorized, role = verify_club_leadership(club, current_user, require_leader_only=True)
    
    if not is_authorized:
        app.logger.warning(f"Unauthorized leadership transfer attempt: User {current_user.id} tried to transfer leadership for club {club_id}")
        return jsonify({'error': 'Unauthorized: Only club leaders can transfer leadership'}), 403

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Check if this is an email verification step
    if 'step' in data and data['step'] == 'verify_email':
        verification_code = data.get('verification_code', '').strip()
        
        if not verification_code:
            return jsonify({'error': 'Verification code is required'}), 400
        
        # Verify the email code
        is_code_valid = airtable_service.verify_email_code(club.leader.email, verification_code)
        
        if is_code_valid:
            return jsonify({
                'success': True,
                'message': 'Email verification successful! You can now transfer leadership.',
                'email_verified': True
            })
        else:
            return jsonify({'error': 'Invalid or expired verification code. Please check your email or request a new code.'}), 400
    
    # Check if this is a request to send verification code
    if 'step' in data and data['step'] == 'send_verification':
        app.logger.info(f"Leadership transfer: Sending verification code to {club.leader.email} for club {club_id}")
        verification_code = airtable_service.send_email_verification(club.leader.email)
        
        if verification_code:
            app.logger.info(f"Leadership transfer: Verification code successfully sent for {club.leader.email}")
            return jsonify({
                'success': True,
                'message': 'Verification code sent to your email. Please check your inbox.',
                'verification_sent': True
            })
        else:
            app.logger.error(f"Leadership transfer: Failed to send verification code to {club.leader.email}")
            return jsonify({'error': 'Failed to send verification code. This may be due to a network timeout. Please try again in a moment.'}), 500
    
    # For actual leadership transfer, require email verification
    email_verified = data.get('email_verified', False)
    if not email_verified:
        return jsonify({
            'error': 'Email verification required for this action',
            'requires_verification': True,
            'verification_email': club.leader.email
        }), 403
    
    # Get new leader user ID
    new_leader_id = data.get('new_leader_id')
    if not new_leader_id:
        return jsonify({'error': 'New leader ID is required'}), 400
    
    # Validate confirmation text
    confirmation_text = data.get('confirmation_text', '').strip().upper()
    if confirmation_text != 'TRANSFER':
        return jsonify({'error': 'Please type TRANSFER to confirm'}), 400
    
    # Get the new leader
    new_leader = User.query.get(new_leader_id)
    if not new_leader:
        return jsonify({'error': 'New leader not found'}), 404
    
    # Check if new leader is a member of the club
    membership = ClubMembership.query.filter_by(club_id=club_id, user_id=new_leader_id).first()
    if not membership:
        return jsonify({'error': 'New leader must be a member of the club'}), 400
    
    # Can't transfer to yourself
    if new_leader_id == current_user.id:
        return jsonify({'error': 'Cannot transfer leadership to yourself'}), 400
    
    # Can't transfer to current co-leader (would create conflict)
    if club.co_leader_id == new_leader_id:
        return jsonify({'error': 'Cannot transfer leadership to current co-leader. Remove co-leader first or choose someone else.'}), 400
    
    try:
        # Store old leader for membership update
        old_leader_id = club.leader_id
        
        # Transfer leadership
        club.leader_id = new_leader_id
        
        # Update the new leader's membership role
        membership.role = 'leader'
        
        # Create or update membership for old leader (downgrade to regular member)
        old_leader_membership = ClubMembership.query.filter_by(club_id=club_id, user_id=old_leader_id).first()
        if not old_leader_membership:
            # Create membership for old leader if they weren't a member
            old_leader_membership = ClubMembership(
                user_id=old_leader_id,
                club_id=club_id,
                role='member',
                joined_at=datetime.now(timezone.utc)
            )
            db.session.add(old_leader_membership)
        else:
            # Update existing membership
            old_leader_membership.role = 'member'
        
        # Clear co-leader if it was the new leader
        if club.co_leader_id == new_leader_id:
            club.co_leader_id = None
        
        club.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        app.logger.info(f"Leadership transferred: Club {club_id} from user {old_leader_id} to user {new_leader_id}")
        
        return jsonify({
            'success': True, 
            'message': f'Leadership successfully transferred to {new_leader.username}',
            'new_leader': {
                'id': new_leader.id,
                'username': new_leader.username,
                'email': new_leader.email
            }
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error transferring leadership: {str(e)}")
        return jsonify({'error': f'Failed to transfer leadership: {str(e)}'}), 500

@api_route('/api/clubs/<int:club_id>/grant-submissions', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def club_grant_submissions(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'GET':
        # Fetch actual grant submissions for this club
        try:
            all_submissions = airtable_service.get_pizza_grant_submissions()
            # Filter submissions by club name
            club_submissions = [
                submission for submission in all_submissions 
                if submission.get('club_name', '').lower() == club.name.lower()
            ]
            return jsonify({'submissions': club_submissions})
        except Exception as e:
            app.logger.error(f"Error fetching grant submissions for club {club_id}: {str(e)}")
            return jsonify({'submissions': []})

    data = request.get_json()
    member_id = data.get('member_id')

    # Only leaders can submit on behalf of others
    if member_id != str(current_user.id) and not is_leader:
        return jsonify({'error': 'You can only submit grants for yourself'}), 403

    # Get member info
    member = User.query.get(member_id)
    if not member:
        return jsonify({'error': 'Member not found'}), 404

    # Prepare submission data for Airtable
    submission_data = {
        'project_name': data.get('project_name', ''),
        'project_hours': data.get('project_hours', '0'),
        'first_name': data.get('first_name', ''),
        'last_name': data.get('last_name', ''),
        'username': member.username,
        'email': data.get('email', ''),
        'birthday': data.get('birthday', ''),
        'age': data.get('age', ''),
        'project_description': data.get('project_description', ''),
        'github_url': data.get('github_url', ''),
        'github_username': data.get('github_username', ''),
        'live_url': data.get('live_url', ''),
        'learning': data.get('learning', ''),
        'doing_well': data.get('doing_well', ''),
        'improve': data.get('improve', ''),
        'address_1': data.get('address_1', ''),
        'address_2': data.get('address_2', ''),
        'city': data.get('city', ''),
        'state': data.get('state', ''),
        'zip': data.get('zip', ''),
        'country': data.get('country', ''),
        'screenshot_url': data.get('screenshot_url', ''),
        'club_name': club.name,
        'leader_email': club.leader.email,
        'grant_type': data.get('grant_type', ''),
        'vendor': data.get('vendor', ''),
        'fund_destination': data.get('fund_destination', '')
    }

    # Submit to Airtable
    result = airtable_service.log_pizza_grant(submission_data)
    if result:
        return jsonify({'message': 'Grant submitted successfully!'})
    else:
        return jsonify({'error': 'Failed to submit grant. Please try again.'}), 500

@api_route('/api/gallery/posts', methods=['GET', 'POST'])
@limiter.limit("100 per hour")
def gallery_posts():
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
        
        # Limit to 50 images max
        if len(images) > 50:
            images = images[:50]
        
        # Verify user is leader or co-leader of the club
        club = Club.query.get_or_404(club_id)
        is_leader = club.leader_id == current_user.id
        is_co_leader = is_user_co_leader(club, current_user)
        
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders can create gallery posts'}), 403
        
        # Security validation
        valid, result = validate_input_with_security(title, "gallery_title", current_user, max_length=200)
        if not valid:
            return jsonify({'error': result}), 403
        title = result
        
        valid, result = validate_input_with_security(description, "gallery_description", current_user, max_length=2000)
        if not valid:
            return jsonify({'error': result}), 403
        description = result
        
        # Create gallery post
        post = GalleryPost(
            club_id=club_id,
            user_id=current_user.id,
            title=title,
            description=description
        )
        post.set_images(images)
        
        # Update quest progress for gallery post
        update_quest_progress(club_id, 'gallery_post', 1)
        
        # Admin can override club name display
        if current_user.is_admin and custom_club_name:
            valid, result = validate_input_with_security(custom_club_name, "custom_club_name", current_user, max_length=100)
            if not valid:
                return jsonify({'error': result}), 403
            # Store custom club name in a new field or use description field with a prefix
            post.description = f"[CUSTOM_CLUB:{result}] {description}"
        
        db.session.add(post)
        db.session.commit()
        
        app.logger.info(f"Gallery post created: ID={post.id}, title='{title}', club_id={club_id}, images={len(images)}")
        
        # Log gallery post to Airtable
        try:
            airtable_success = airtable_service.log_gallery_post(
                post_title=title,
                description=description,
                photos=images,
                club_name=club.name,
                author_username=current_user.username
            )
            if airtable_success:
                app.logger.info(f"Gallery post {post.id} successfully logged to Airtable")
            else:
                app.logger.warning(f"Failed to log gallery post {post.id} to Airtable")
        except Exception as e:
            app.logger.error(f"Exception logging gallery post {post.id} to Airtable: {str(e)}")
        
        # Create audit log for gallery post creation
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
    
    # GET request - return all gallery posts
    try:
        posts = GalleryPost.query.order_by(GalleryPost.created_at.desc()).all()
        posts_data = []
        
        app.logger.info(f"Retrieved {len(posts)} gallery posts from database")
        
        for post in posts:
            try:
                # Get club and user info safely
                club = Club.query.get(post.club_id)
                user = User.query.get(post.user_id)
                
                if not club or not user:
                    app.logger.warning(f"Skipping post {post.id}: missing club ({club}) or user ({user})")
                    continue
                
                # Check for admin custom club name override
                display_club_name = club.name
                display_description = post.description
                
                if post.description.startswith('[CUSTOM_CLUB:'):
                    # Extract custom club name and actual description
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
                app.logger.debug(f"Gallery post {post.id}: '{post.title}' by {user.username} from {club.name}, {len(post.get_images())} images")
                
            except Exception as e:
                app.logger.error(f"Error processing gallery post {post.id}: {str(e)}")
                continue
        
        app.logger.info(f"Returning {len(posts_data)} gallery posts to frontend")
        return jsonify({'posts': posts_data})
        
    except Exception as e:
        app.logger.error(f"Error fetching gallery posts: {str(e)}")
        db.session.rollback()
        return jsonify({'posts': []})

@api_route('/api/gallery/posts/<int:post_id>', methods=['DELETE'])
@login_required
@limiter.limit("50 per hour")
def delete_gallery_post(post_id):
    current_user = get_current_user()
    
    # Only admins can delete gallery posts
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    post = GalleryPost.query.get_or_404(post_id)
    
    try:
        # Get images and related data before deletion
        images = post.get_images()
        post_title = post.title
        post_author_name = post.user.username if post.user else 'Unknown'
        club_name = post.club.name if post.club else 'Unknown'
        club = post.club
        
        # Deduct 100 tokens from the club if it has enough tokens
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
                app.logger.warning(f"Failed to deduct tokens for gallery post deletion: {error_msg}")
        
        # Clean up uploaded images
        for image_url in images:
            if 'static/uploads/' in image_url:
                try:
                    filename = image_url.split('static/uploads/')[-1]
                    file_path = os.path.join(app.root_path, 'static', 'uploads', filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        app.logger.info(f"Cleaned up image file: {file_path}")
                except Exception as e:
                    app.logger.warning(f"Failed to clean up image file: {str(e)}")
        
        # Delete the post
        db.session.delete(post)
        db.session.commit()
        
        # Create audit log after successful deletion
        create_audit_log(
            action_type='gallery_post_delete',
            description=f"Admin {current_user.username} deleted gallery post '{post_title}'",
            user=current_user,
            target_type='gallery_post',
            target_id=post_id,
            details={
                'post_title': post_title,
                'post_author': post_author_name,
                'club_name': club_name,
                'images_count': len(images)
            },
            severity='warning',
            admin_action=True,
            category='admin'
        )
        
        app.logger.info(f"Admin {current_user.username} deleted gallery post {post_id}")
        return jsonify({'success': True, 'message': 'Gallery post deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting gallery post {post_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete gallery post'}), 500

@api_route('/api/clubs/<int:club_id>/purchase-requests', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def club_purchase_requests(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)

    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()

    if not is_leader and not is_co_leader and not is_member:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        # Only leaders and co-leaders can submit purchase requests
        if not is_leader and not is_co_leader:
            return jsonify({'error': 'Only club leaders and co-leaders can submit purchase requests'}), 403

        data = request.get_json()
        
        # Validate required fields
        required_fields = ['purchase_type', 'description', 'reason', 'fulfillment_method', 'amount']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

        # Validate amount
        try:
            amount = float(data.get('amount', 0))
            if amount <= 0:
                return jsonify({'error': 'Amount must be greater than 0'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount format'}), 400

        # Check if amount exceeds club balance
        if amount > (club.tokens / 100.0):
            return jsonify({'error': f'Amount cannot exceed club balance of {club.tokens} tokens'}), 400

        # Prepare data for Grant Fulfillment table
        purchase_data = {
            'leader_first_name': data.get('leader_first_name', ''),
            'leader_last_name': data.get('leader_last_name', ''),
            'leader_email': data.get('leader_email', ''),
            'purchase_type': data.get('purchase_type'),
            'description': data.get('description'),
            'reason': data.get('reason'),
            'fulfillment_method': data.get('fulfillment_method'),
            'amount': amount,
            'club_name': data.get('club_name', club.name)
        }

        # Submit to Airtable Grant Fulfillment table
        result = airtable_service.submit_purchase_request(purchase_data)
        
        if result:
            # Create transaction record for the purchase request (this will update balance automatically)
            try:
                success, tx_result = create_club_transaction(
                    club_id=club_id,
                    transaction_type='purchase',
                    amount=-int(amount * 100),  # Convert to tokens (negative for debit)
                    description=f"Purchase request: {data.get('description')} ({data.get('purchase_type')})",
                    user_id=current_user.id,
                    reference_type='purchase_request',
                    created_by=current_user.id
                )
                
                if success:
                    app.logger.info(f"Transaction recorded for purchase request: {int(amount * 100)} tokens deducted")
                else:
                    app.logger.error(f"Failed to record transaction for purchase request: {tx_result}")
            except Exception as tx_error:
                app.logger.error(f"Exception while recording purchase request transaction: {str(tx_error)}")
            
            return jsonify({
                'message': 'Purchase request submitted successfully!',
                'new_balance': float(club.balance)
            })
        else:
            return jsonify({'error': 'Failed to submit purchase request. Please try again.'}), 500

    else:
        # GET request - return empty list for now since we don't have a method to fetch from Grant Fulfillment
        return jsonify({'requests': []})

@api_route('/api/upload-screenshot', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def upload_screenshot():
    app.logger.info("Screenshot upload endpoint called")
    
    if 'screenshot' not in request.files:
        app.logger.error("No screenshot file in request")
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400

    file = request.files['screenshot']
    app.logger.info(f"File received: {file.filename}, content_type: {file.content_type}")
    
    if file.filename == '':
        app.logger.error("Empty filename")
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    # Enhanced file validation
    if not file.content_type.startswith('image/'):
        app.logger.error(f"Invalid content type: {file.content_type}")
        return jsonify({'success': False, 'error': 'File must be an image'}), 400

    # Additional MIME type validation
    allowed_mime_types = {'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'}
    if file.content_type not in allowed_mime_types:
        app.logger.error(f"Disallowed MIME type: {file.content_type}")
        return jsonify({'success': False, 'error': 'Invalid image format. Only JPEG, PNG, GIF, and WebP allowed.'}), 400

    # Check file size (max 50MB)
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    max_size = 50 * 1024 * 1024  # 50MB
    if file_size > max_size:
        return jsonify({'success': False, 'error': 'File too large. Maximum size is 50MB.'}), 400

    try:
        import uuid
        import os
        from werkzeug.utils import secure_filename
        
        # Secure the filename to prevent path traversal
        secured_filename = secure_filename(file.filename)
        if not secured_filename:
            secured_filename = 'upload.jpg'
        
        # Get file extension and validate it
        file_extension = os.path.splitext(secured_filename)[1].lower()
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
        
        if file_extension not in allowed_extensions:
            return jsonify({'success': False, 'error': 'Invalid file type. Only images allowed.'}), 400
        
        # Generate a unique filename with validated extension
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        
        # Create uploads directory if it doesn't exist
        upload_dir = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        # Construct safe file path - prevent directory traversal
        file_path = os.path.abspath(os.path.join(upload_dir, unique_filename))
        
        # Ensure the file path is within the upload directory
        if not file_path.startswith(os.path.abspath(upload_dir)):
            app.logger.error(f"Path traversal attempt detected: {file_path}")
            return jsonify({'success': False, 'error': 'Invalid file path'}), 400
        
        # Save file securely
        file.save(file_path)
        
        # Generate accessible URL with secure filename
        file_url = f"{request.url_root}static/uploads/{unique_filename}"
        
        app.logger.info(f"Screenshot saved successfully: {file_path}")
        app.logger.info(f"Generated URL: {file_url}")
        
        return jsonify({'success': True, 'url': file_url})
    except Exception as e:
        app.logger.error(f"Error uploading screenshot: {str(e)}")
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@api_route('/api/upload-images', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def upload_images():
    """Upload multiple images to HackClub CDN"""
    current_user = get_current_user()
    app.logger.info("Gallery images upload endpoint called")
    
    try:
        data = request.get_json()
        if not data or 'images' not in data:
            return jsonify({'success': False, 'error': 'No images provided'}), 400
        
        base64_images = data['images']
        if not isinstance(base64_images, list):
            return jsonify({'success': False, 'error': 'Images must be provided as an array'}), 400
        
        # Check for admin bulk upload mode
        bulk_upload = data.get('bulk_upload', False)
        
        # Regular users: max 50 images, Admins in bulk mode: max 200 images
        max_images = 200 if (current_user.is_admin and bulk_upload) else 50
        
        if len(base64_images) > max_images:
            return jsonify({'success': False, 'error': f'Maximum {max_images} images allowed'}), 400
        
        # Get HackClub CDN API token from environment
        cdn_token = os.getenv('HACKCLUB_CDN_TOKEN')
        if not cdn_token:
            app.logger.error("HACKCLUB_CDN_TOKEN not configured")
            return jsonify({'success': False, 'error': 'CDN service not configured'}), 500
        
        # Upload images to HackClub CDN
        uploaded_urls = []
        cdn_url_list = []
        
        for i, base64_data in enumerate(base64_images):
            if not base64_data or not isinstance(base64_data, str):
                continue
                
            try:
                # Parse base64 data URL
                if not base64_data.startswith('data:image/'):
                    continue
                
                # Extract MIME type and base64 data
                header, data_part = base64_data.split(',', 1)
                mime_type = header.split(':')[1].split(';')[0]
                
                # Validate MIME type
                allowed_mime_types = {'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'}
                if mime_type not in allowed_mime_types:
                    app.logger.warning(f"Skipping invalid MIME type: {mime_type}")
                    continue
                
                # Decode base64 and check file size (max 50MB per image)
                import base64
                image_data = base64.b64decode(data_part)
                max_size = 50 * 1024 * 1024  # 50MB
                if len(image_data) > max_size:
                    app.logger.warning(f"Skipping image {i}: too large ({len(image_data)} bytes, max {max_size})")
                    continue
                
                # Create temporary file for upload
                import tempfile
                import uuid
                ext_map = {
                    'image/jpeg': '.jpg',
                    'image/jpg': '.jpg', 
                    'image/png': '.png',
                    'image/gif': '.gif',
                    'image/webp': '.webp'
                }
                file_ext = ext_map.get(mime_type, '.jpg')
                
                with tempfile.NamedTemporaryFile(suffix=file_ext, delete=False) as temp_file:
                    temp_file.write(image_data)
                    temp_file_path = temp_file.name
                
                # Create public URL for the temp file that CDN can access
                # Since CDN expects URLs, we need to serve the temp file temporarily
                temp_filename = f"temp_{uuid.uuid4()}{file_ext}"
                temp_upload_dir = os.path.join(app.root_path, 'static', 'temp')
                os.makedirs(temp_upload_dir, exist_ok=True)
                temp_public_path = os.path.join(temp_upload_dir, temp_filename)
                
                # Copy temp file to public location
                import shutil
                shutil.copy2(temp_file_path, temp_public_path)
                os.unlink(temp_file_path)  # Remove original temp file
                
                # Create public URL for CDN to access
                temp_url = f"{request.url_root}static/temp/{temp_filename}"
                cdn_url_list.append(temp_url)
                
                app.logger.info(f"Prepared image {i} for CDN upload: {temp_filename} ({len(image_data)} bytes)")
                
            except Exception as e:
                app.logger.error(f"Error processing image {i}: {str(e)}")
                continue
        
        if not cdn_url_list:
            return jsonify({'success': False, 'error': 'No valid images could be processed'}), 400
        
        # Upload to HackClub CDN
        try:
            import requests
            cdn_response = requests.post(
                'https://cdn.hackclub.com/api/v3/new',
                headers={
                    'Authorization': f'Bearer {cdn_token}',
                    'Content-Type': 'application/json'
                },
                json=cdn_url_list,
                timeout=30
            )
            
            if cdn_response.status_code != 200:
                app.logger.error(f"CDN upload failed: {cdn_response.status_code} - {cdn_response.text}")
                return jsonify({'success': False, 'error': 'Failed to upload to CDN'}), 500
            
            cdn_data = cdn_response.json()
            
            if 'files' in cdn_data:
                uploaded_urls = [file_info['deployedUrl'] for file_info in cdn_data['files']]
            else:
                app.logger.error(f"Unexpected CDN response format: {cdn_data}")
                return jsonify({'success': False, 'error': 'Unexpected CDN response format'}), 500
            
        except requests.RequestException as e:
            app.logger.error(f"Error uploading to CDN: {str(e)}")
            return jsonify({'success': False, 'error': 'Failed to connect to CDN service'}), 500
        
        finally:
            # Clean up temporary files
            temp_upload_dir = os.path.join(app.root_path, 'static', 'temp')
            for temp_url in cdn_url_list:
                temp_filename = temp_url.split('/')[-1]
                temp_file_path = os.path.join(temp_upload_dir, temp_filename)
                try:
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)
                except Exception as e:
                    app.logger.warning(f"Failed to clean up temp file {temp_file_path}: {str(e)}")
        
        if not uploaded_urls:
            return jsonify({'success': False, 'error': 'No images were successfully uploaded to CDN'}), 400
        
        app.logger.info(f"Successfully uploaded {len(uploaded_urls)} images to HackClub CDN (bulk_upload={bulk_upload})")
        return jsonify({'success': True, 'urls': uploaded_urls})
        
    except Exception as e:
        app.logger.error(f"Error uploading gallery images: {str(e)}")
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@api_route('/api/blog/upload-images', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def upload_blog_images():
    """Upload multiple images to HackClub CDN for blog posts"""
    current_user = get_current_user()
    
    if not current_user.is_admin and not current_user.is_reviewer:
        return jsonify({'error': 'Only admins and reviewers can upload blog images'}), 403
    
    try:
        data = request.get_json()
        if not data or 'images' not in data:
            app.logger.error("No images in request data")
            return jsonify({'error': 'No images provided'}), 400
        
        images = data['images']
        if not images:
            app.logger.error("Empty images array")
            return jsonify({'error': 'No images provided'}), 400
        
        app.logger.info(f"Processing {len(images)} images for blog upload")
        
        # Validate image count
        max_images = 50
        if len(images) > max_images:
            return jsonify({'error': f'Maximum {max_images} images allowed'}), 400
        
        # HackClub CDN token
        cdn_token = os.getenv('HACKCLUB_CDN_TOKEN')
        if not cdn_token:
            return jsonify({'error': 'CDN not configured'}), 500
        
        # Process each image
        cdn_url_list = []
        temp_files = []
        
        for i, image_data in enumerate(images):
            try:
                # Validate data URL format
                if not image_data.startswith('data:image/'):
                    continue
                
                # Extract MIME type and base64 data
                header, base64_data = image_data.split(',', 1)
                mime_type = header.split(';')[0].split(':')[1]
                
                # Validate MIME type
                allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp']
                if mime_type not in allowed_types:
                    continue
                
                # Decode base64
                try:
                    file_data = base64.b64decode(base64_data)
                except Exception as decode_error:
                    app.logger.error(f"Base64 decode error for image {i}: {str(decode_error)}")
                    continue
                
                # Validate file size (50MB max)
                if len(file_data) > 50 * 1024 * 1024:
                    continue
                
                # Create temporary file
                temp_filename = f"blog_temp_{current_user.id}_{i}_{int(datetime.now().timestamp())}.{mime_type.split('/')[1]}"
                temp_path = os.path.join('static', 'temp', temp_filename)
                
                # Ensure temp directory exists
                os.makedirs(os.path.dirname(temp_path), exist_ok=True)
                
                # Write file
                with open(temp_path, 'wb') as f:
                    f.write(file_data)
                
                temp_files.append(temp_path)
                
                # Create public URL for CDN
                public_url = f"{request.url_root}{temp_path}"
                cdn_url_list.append(public_url)
                
            except Exception as e:
                app.logger.error(f"Error processing blog image {i}: {str(e)}")
                continue
        
        if not cdn_url_list:
            return jsonify({'error': 'No valid images processed'}), 400
        
        # Upload to HackClub CDN
        try:
            cdn_response = requests.post(
                'https://cdn.hackclub.com/api/v3/new',
                headers={
                    'Authorization': f'Bearer {cdn_token}',
                    'Content-Type': 'application/json'
                },
                json=cdn_url_list,
                timeout=30
            )
            
            if cdn_response.status_code != 200:
                app.logger.error(f"CDN upload failed with status {cdn_response.status_code}: {cdn_response.text}")
                return jsonify({'error': 'CDN upload failed'}), 500
                
            cdn_data = cdn_response.json()
            
            if 'files' in cdn_data:
                uploaded_urls = []
                for file_info in cdn_data['files']:
                    if 'deployedUrl' in file_info:
                        uploaded_urls.append(file_info['deployedUrl'])
                
                return jsonify({'success': True, 'urls': uploaded_urls})
            else:
                return jsonify({'error': 'Invalid CDN response'}), 500
                
        except requests.exceptions.Timeout:
            return jsonify({'error': 'CDN upload timeout'}), 500
        except requests.exceptions.RequestException as e:
            app.logger.error(f"CDN request failed: {str(e)}")
            return jsonify({'error': 'CDN upload failed'}), 500
        
        finally:
            # Clean up temporary files
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception as e:
                    app.logger.error(f"Error cleaning up temp file {temp_file}: {str(e)}")
        
    except Exception as e:
        app.logger.error(f"Error uploading blog images: {str(e)}")
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@api_route('/api/user/me', methods=['GET'])
@login_required
def get_current_user_info():
    """Get current user information"""
    try:
        current_user = get_current_user()
        return jsonify({
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'is_admin': current_user.is_admin,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name
        })
    except Exception as e:
        app.logger.error(f"Error getting current user info: {str(e)}")
        return jsonify({'error': 'Failed to get user info'}), 500

@api_route('/api/user/<int:user_id>', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_user_info(user_id):
    current_user = get_current_user()

    # Only allow users to access their own info or club leaders to access member info
    if user_id != current_user.id:
        # Check if current user is a leader of any club where this user is a member
        is_leader = False
        led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
        for club in led_clubs:
            membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user_id).first()
            if membership or club.leader_id == user_id:
                is_leader = True
                break

        if not is_leader:
            return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'birthday': user.birthday.isoformat() if user.birthday else None
    })

@api_route('/api/hackatime/projects/<int:user_id>', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_hackatime_projects(user_id):
    current_user = get_current_user()
    app.logger.info(f"get_hackatime_projects: Request from user {current_user.username} (ID: {current_user.id}) for user_id {user_id}")

    # Only allow users to access their own data or club leaders to access member data
    if user_id != current_user.id:
        app.logger.info(f"get_hackatime_projects: Cross-user access requested, checking leader permissions")
        is_leader = False
        led_clubs = Club.query.filter_by(leader_id=current_user.id).all()
        app.logger.info(f"get_hackatime_projects: Current user leads {len(led_clubs)} clubs")
        
        for club in led_clubs:
            membership = ClubMembership.query.filter_by(club_id=club.id, user_id=user_id).first()
            if membership or club.leader_id == user_id:
                is_leader = True
                app.logger.info(f"get_hackatime_projects: Access granted - user is member/leader of club {club.id}")
                break

        if not is_leader:
            app.logger.warning(f"get_hackatime_projects: Access denied - user {current_user.id} is not leader of user {user_id}")
            return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get_or_404(user_id)
    app.logger.info(f"get_hackatime_projects: Target user: {user.username} (ID: {user.id})")

    if not user.hackatime_api_key:
        app.logger.warning(f"get_hackatime_projects: User {user.username} has no Hackatime API key configured")
        return jsonify({'error': 'User has not configured Hackatime API key'}), 400

    app.logger.info(f"get_hackatime_projects: User {user.username} has API key configured, fetching projects")
    projects = hackatime_service.get_user_projects(user.hackatime_api_key)

    app.logger.info(f"get_hackatime_projects: Returning {len(projects)} projects for user {user.username}")
    response_data = {
        'username': user.username,
        'projects': projects
    }

    return jsonify(response_data)

@api_route('/api/admin/audit-logs', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_get_audit_logs():
    """Get audit logs with filtering and pagination"""
    current_user = get_current_user()
    
    # Get pagination parameters
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 50, type=int)))
    
    # Get filter parameters
    search = sanitize_string(request.args.get('search', ''), max_length=100).strip()
    category = request.args.get('category', '').strip()
    action_type = request.args.get('action_type', '').strip()
    severity = request.args.get('severity', '').strip()
    admin_only = request.args.get('admin_only', '').lower() == 'true'
    user_id = request.args.get('user_id', type=int)
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    sort_order = request.args.get('sort', 'desc').strip()  # asc or desc
    
    # Build query
    query = AuditLog.query
    
    # Apply filters
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                AuditLog.description.ilike(search_term),
                AuditLog.action_type.ilike(search_term),
                User.username.ilike(search_term)
            )
        ).join(User, AuditLog.user_id == User.id, isouter=True)
    
    if category:
        query = query.filter(AuditLog.action_category == category)
    
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    
    if severity:
        query = query.filter(AuditLog.severity == severity)
    
    if admin_only:
        query = query.filter(AuditLog.admin_action == True)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if start_date:
        try:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= start_dt)
        except ValueError:
            pass
    
    if end_date:
        try:
            end_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.timestamp < end_dt)
        except ValueError:
            pass
    
    # Apply sorting
    if sort_order == 'asc':
        query = query.order_by(AuditLog.timestamp.asc())
    else:
        query = query.order_by(AuditLog.timestamp.desc())
    
    # Get paginated results
    logs = query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    # Log the admin audit log access
    create_audit_log(
        action_type='admin_action',
        description=f"Admin {current_user.username} accessed audit logs",
        user=current_user,
        details={
            'filters': {
                'category': category,
                'action_type': action_type,
                'severity': severity,
                'admin_only': admin_only,
                'search': search
            }
        },
        admin_action=True,
        category='admin'
    )
    
    return jsonify({
        'logs': [log.to_dict() for log in logs.items],
        'pagination': {
            'page': logs.page,
            'pages': logs.pages,
            'per_page': logs.per_page,
            'total': logs.total,
            'has_next': logs.has_next,
            'has_prev': logs.has_prev
        }
    })

@api_route('/api/admin/users', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_get_users():
    current_user = get_current_user()

    # Permission check
    if not (current_user.has_permission('users.view') or current_user.is_admin):
        return jsonify({'error': 'You do not have permission to view users'}), 403

    # Get pagination parameters with sanitization
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, max(1, request.args.get('per_page', 10, type=int)))
    search = sanitize_string(request.args.get('search', ''), max_length=100).strip()
    sort = request.args.get('sort', 'created_at-desc')

    # Build query
    query = User.query
    
    # Apply search filter if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                User.username.ilike(search_term),
                User.email.ilike(search_term)
            )
        )
    
    # Apply sorting
    if sort == 'created_at-desc':
        query = query.order_by(User.created_at.desc())
    elif sort == 'created_at-asc':
        query = query.order_by(User.created_at.asc())
    elif sort == 'username-asc':
        query = query.order_by(User.username.asc())
    elif sort == 'username-desc':
        query = query.order_by(User.username.desc())
    elif sort == 'email-asc':
        query = query.order_by(User.email.asc())
    elif sort == 'email-desc':
        query = query.order_by(User.email.desc())
    elif sort == 'suspended-desc':
        # Suspended users first: Handle NULL values by treating them as FALSE
        from sqlalchemy import case
        query = query.order_by(
            case((User.is_suspended == True, 1), else_=0).desc(),
            User.created_at.desc()
        )
    elif sort == 'suspended-asc':
        # Active users first: Handle NULL values by treating them as FALSE
        from sqlalchemy import case
        query = query.order_by(
            case((User.is_suspended == True, 1), else_=0).asc(),
            User.created_at.desc()
        )
    elif sort == 'role-admin':
        # Admins first: Users with admin-related roles first
        # We'll need to join with roles and sort in Python since relationship is complex
        query = query.outerjoin(UserRole).outerjoin(Role)
        query = query.order_by(
            case(
                (Role.name.in_(['super-admin', 'admin', 'users-admin']), 0),
                else_=1
            ),
            User.created_at.desc()
        )
    elif sort == 'role-user':
        # Regular users first: Users without admin-related roles first
        query = query.outerjoin(UserRole).outerjoin(Role)
        query = query.order_by(
            case(
                (Role.name.in_(['super-admin', 'admin', 'users-admin']), 1),
                else_=0
            ),
            User.created_at.desc()
        )
    else:
        # Default to newest first
        query = query.order_by(User.created_at.desc())
    
    # Apply pagination
    users_paginated = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    users_data = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_reviewer': user.is_reviewer,
        'is_suspended': user.is_suspended,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'registration_ip': user.registration_ip,
        'last_login_ip': user.last_login_ip,
        'total_ips': len(user.get_all_ips()),
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    } for user in users_paginated.items]

    return jsonify({
        'items': users_data,
        'total': users_paginated.total,
        'page': page,
        'per_page': per_page,
        'pages': users_paginated.pages,
        'has_next': users_paginated.has_next,
        'has_prev': users_paginated.has_prev
    })

@api_route('/api/admin/users/group-by-ip', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_users_group_by_ip():
    current_user = get_current_user()
    
    # Get pagination and sorting parameters
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(20, max(1, request.args.get('per_page', 4, type=int)))
    sort_by = request.args.get('sort', 'users-desc')  # users-desc, users-asc, ip-asc, ip-desc
    
    # Get all unique IPs and their user counts using ORM
    from sqlalchemy import func, union_all, select
    
    # Build subqueries for registration IPs and login IPs
    reg_ip_query = db.session.query(
        User.registration_ip.label('ip'),
        func.count(User.id).label('user_count'),
        func.cast('Registration IP', db.String).label('type')
    ).filter(User.registration_ip.isnot(None)).group_by(User.registration_ip)
    
    login_ip_query = db.session.query(
        User.last_login_ip.label('ip'),
        func.count(User.id).label('user_count'),
        func.cast('Login IP', db.String).label('type')
    ).filter(
        User.last_login_ip.isnot(None),
        ~User.last_login_ip.in_(
            db.session.query(User.registration_ip).filter(User.registration_ip.isnot(None))
        )
    ).group_by(User.last_login_ip)
    
    # Combine both queries
    combined_query = union_all(reg_ip_query.statement, login_ip_query.statement).alias('ip_groups')
    
    # Group by IP and count users
    ip_groups_query = db.session.query(
        combined_query.c.ip,
        func.sum(combined_query.c.user_count).label('total_users'),
        func.array_agg(func.distinct(combined_query.c.type)).label('types')
    ).group_by(combined_query.c.ip)
    
    # Apply sorting
    if sort_by == 'users-desc':
        ip_groups_query = ip_groups_query.order_by(func.sum(combined_query.c.user_count).desc())
    elif sort_by == 'users-asc':
        ip_groups_query = ip_groups_query.order_by(func.sum(combined_query.c.user_count).asc())
    elif sort_by == 'ip-asc':
        ip_groups_query = ip_groups_query.order_by(combined_query.c.ip.asc())
    elif sort_by == 'ip-desc':
        ip_groups_query = ip_groups_query.order_by(combined_query.c.ip.desc())
    
    # Get total count for pagination
    total_count = ip_groups_query.count()
    
    # Apply pagination
    offset = (page - 1) * per_page
    paginated_ips = ip_groups_query.offset(offset).limit(per_page).all()
    
    # Now get users for each IP in the current page
    groups = []
    for ip_row in paginated_ips:
        ip = ip_row[0]
        user_count = ip_row[1]
        ip_types = ip_row[2] if ip_row[2] else []
        
        # Get users for this IP using ORM (limit to prevent huge queries)
        users_for_ip = db.session.query(User).filter(
            db.or_(User.registration_ip == ip, User.last_login_ip == ip)
        ).order_by(User.username).limit(50).all()
        
        users_data = []
        for user in users_for_ip:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_reviewer': user.is_reviewer,
                'is_suspended': user.is_suspended,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'clubs_led': len(user.led_clubs),
                'clubs_joined': len(user.club_memberships)
            })
        
        groups.append({
            'ip': ip,
            'users': users_data,
            'type': ' & '.join(ip_types) if len(ip_types) > 1 else (ip_types[0] if ip_types else 'Unknown')
        })
    
    return jsonify({
        'groups': groups,
        'total_groups': total_count,
        'total_users_with_ips': 0,  # Skip this expensive calculation
        'page': page,
        'per_page': per_page,
        'total_pages': (total_count + per_page - 1) // per_page,
        'has_next': page * per_page < total_count,
        'has_prev': page > 1
    })

@api_route('/api/admin/users/group-by-club', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_users_group_by_club():
    current_user = get_current_user()
    
    # Get pagination and sorting parameters
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(20, max(1, request.args.get('per_page', 4, type=int)))
    sort_by = request.args.get('sort', 'users-desc')  # users-desc, users-asc, name-asc, name-desc
    
    from sqlalchemy import func, case
    
    # Get clubs with user counts using ORM
    club_user_counts = db.session.query(
        Club.id,
        Club.name,
        Club.join_code,
        (func.count(ClubMembership.user_id) + 
         case((Club.leader_id.isnot(None), 1), else_=0)).label('total_users')
    ).outerjoin(
        ClubMembership, 
        db.and_(Club.id == ClubMembership.club_id, ClubMembership.user_id != Club.leader_id)
    ).group_by(Club.id, Club.name, Club.join_code, Club.leader_id).having(
        (func.count(ClubMembership.user_id) + 
         case((Club.leader_id.isnot(None), 1), else_=0)) > 0
    )
    
    # Apply sorting
    if sort_by == 'users-desc':
        club_user_counts = club_user_counts.order_by(func.text('total_users DESC'))
    elif sort_by == 'users-asc':
        club_user_counts = club_user_counts.order_by(func.text('total_users ASC'))
    elif sort_by == 'name-asc':
        club_user_counts = club_user_counts.order_by(Club.name.asc())
    elif sort_by == 'name-desc':
        club_user_counts = club_user_counts.order_by(Club.name.desc())
    
    # Get users without clubs count
    users_without_clubs_count = db.session.query(User).filter(
        ~User.id.in_(
            db.session.query(Club.leader_id).filter(Club.leader_id.isnot(None))
        ),
        ~User.id.in_(
            db.session.query(ClubMembership.user_id).filter(ClubMembership.user_id.isnot(None))
        )
    ).count()
    
    # Get total count for pagination
    total_clubs_with_users = club_user_counts.count()
    total_groups = total_clubs_with_users + (1 if users_without_clubs_count > 0 else 0)
    
    # Apply pagination (save space for orphans group if needed)
    clubs_per_page = per_page - 1 if users_without_clubs_count > 0 else per_page
    offset = (page - 1) * per_page
    paginated_clubs = club_user_counts.offset(offset).limit(clubs_per_page).all()
    
    groups = []
    
    # Process club groups
    for club_row in paginated_clubs:
        club_id, club_name, club_code, user_count = club_row
        
        # Get users for this club using ORM
        club_users = []
        
        # Add leader first
        club = Club.query.get(club_id)
        if club and club.leader:
            club_users.append({
                'id': club.leader.id,
                'username': club.leader.username,
                'email': club.leader.email,
                'is_admin': club.leader.is_admin,
                'is_reviewer': club.leader.is_reviewer,
                'is_suspended': club.leader.is_suspended,
                'created_at': club.leader.created_at.isoformat() if club.leader.created_at else None,
                'role': 'Leader'
            })
        
        # Add members
        members = db.session.query(User).join(ClubMembership).filter(
            ClubMembership.club_id == club_id,
            ClubMembership.user_id != club.leader_id if club else True
        ).order_by(User.username).limit(49).all()  # Leave room for leader
        
        for member in members:
            club_users.append({
                'id': member.id,
                'username': member.username,
                'email': member.email,
                'is_admin': member.is_admin,
                'is_reviewer': member.is_reviewer,
                'is_suspended': member.is_suspended,
                'created_at': member.created_at.isoformat() if member.created_at else None,
                'role': 'Member'
            })
        
        groups.append({
            'club_id': club_id,
            'club_name': club_name,
            'club_code': club_code,
            'users': club_users,
            'total_users': len(club_users)
        })
    
    # Add users without clubs group if it should appear on this page
    if users_without_clubs_count > 0:
        # Simple logic: include orphans if there's room on current page
        should_include_orphans = len(groups) < per_page
        
        if should_include_orphans:
            # Get sample users without clubs
            orphan_users = db.session.query(User).filter(
                ~User.id.in_(
                    db.session.query(Club.leader_id).filter(Club.leader_id.isnot(None))
                ),
                ~User.id.in_(
                    db.session.query(ClubMembership.user_id).filter(ClubMembership.user_id.isnot(None))
                )
            ).order_by(User.username).limit(50).all()
            
            orphan_users_data = []
            for user in orphan_users:
                orphan_users_data.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_admin': user.is_admin,
                    'is_reviewer': user.is_reviewer,
                    'is_suspended': user.is_suspended,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'role': 'No Club'
                })
            
            groups.append({
                'club_name': 'Users Without Clubs',
                'club_code': '',
                'users': orphan_users_data,
                'total_users': users_without_clubs_count,
                'isSpecial': True
            })
    
    return jsonify({
        'groups': groups,
        'total_clubs': total_clubs_with_users,
        'total_users_in_clubs': 0,  # Skip expensive calculation
        'users_without_clubs_count': users_without_clubs_count,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_groups + per_page - 1) // per_page,
        'total_groups': total_groups,
        'has_next': page * per_page < total_groups,
        'has_prev': page > 1
    })

@api_route('/api/admin/clubs', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_get_clubs():
    current_user = get_current_user()
    if not (current_user.has_permission('clubs.view') or current_user.is_admin):
        return jsonify({'error': 'You do not have permission to view clubs'}), 403

    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '').strip()
    
    # Limit per_page to reasonable values
    per_page = min(per_page, 100)
    
    # Build query
    query = Club.query
    
    # Apply search filter if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Club.name.ilike(search_term),
                Club.description.ilike(search_term),
                Club.location.ilike(search_term)
            )
        )
    
    # Apply pagination
    clubs_paginated = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    clubs_data = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': club.leader.username if club.leader else 'No Leader',
        'leader_email': club.leader.email if club.leader else 'No Email',
        'leader_id': club.leader_id,
        'member_count': len(club.members) + (1 if club.leader else 0),  # +1 for leader if exists
        'balance': float(club.balance),
        'created_at': club.created_at.isoformat() if club.created_at else None,
        'join_code': club.join_code,
        'sync_immune': club.sync_immune
    } for club in clubs_paginated.items]

    return jsonify({
        'items': clubs_data,
        'total': clubs_paginated.total,
        'page': page,
        'per_page': per_page,
        'pages': clubs_paginated.pages,
        'has_next': clubs_paginated.has_next,
        'has_prev': clubs_paginated.has_prev
    })


@api_route('/api/admin/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
@limiter.limit("50 per hour")
def admin_manage_user(user_id):
    current_user = get_current_user()

    user = User.query.get_or_404(user_id)

    if request.method == 'GET':
        if not (current_user.has_permission('users.view') or current_user.is_admin):
            return jsonify({'error': 'You do not have permission to view users'}), 403
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_admin': user.is_admin,
            'is_reviewer': user.is_reviewer,
            'is_suspended': user.is_suspended,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'registration_ip': user.registration_ip,
            'last_login_ip': user.last_login_ip
        }
        return jsonify(user_data)

    if request.method == 'DELETE':
        if not (current_user.has_permission('users.delete') or current_user.is_admin):
            return jsonify({'error': 'You do not have permission to delete users'}), 403

        try:
            # Don't allow deleting super admin
            if user.email == 'ethan@hackclub.com':
                return jsonify({'error': 'Cannot delete super admin'}), 400

            # Delete related data in correct order to avoid foreign key violations
            # Delete club assignments for clubs led by this user
            led_clubs = Club.query.filter_by(leader_id=user_id).all()
            for club in led_clubs:
                ClubAssignment.query.filter_by(club_id=club.id).delete()
                ClubPost.query.filter_by(club_id=club.id).delete()
                ClubMeeting.query.filter_by(club_id=club.id).delete()
                ClubResource.query.filter_by(club_id=club.id).delete()
                ClubProject.query.filter_by(club_id=club.id).delete()
                ClubMembership.query.filter_by(club_id=club.id).delete()
                db.session.delete(club)

            # Delete user's own posts, projects, etc.
            ClubPost.query.filter_by(user_id=user_id).delete()
            ClubProject.query.filter_by(user_id=user_id).delete()

            # Delete user's memberships
            ClubMembership.query.filter_by(user_id=user_id).delete()

            # Finally delete the user
            db.session.delete(user)
            db.session.commit()

            app.logger.info(f"Admin {current_user.username} deleted user {user.username} (ID: {user_id})")
            return jsonify({'message': 'User deleted successfully'})

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting user {user_id}: {str(e)}")
            return jsonify({'error': 'Failed to delete user due to database constraints'}), 500

    if request.method == 'PUT':
        if not (current_user.has_permission('users.edit') or current_user.is_admin):
            return jsonify({'error': 'You do not have permission to edit users'}), 403

        try:
            data = request.get_json()

            if 'username' in data:
                valid, result = validate_username(data['username'])
                if not valid:
                    return jsonify({'error': result}), 400

                existing_user = User.query.filter_by(username=result).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({'error': 'Username already taken'}), 400
                user.username = result

            if 'email' in data:
                valid, result = validate_email(data['email'])
                if not valid:
                    return jsonify({'error': result}), 400

                existing_user = User.query.filter_by(email=result).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({'error': 'Email already registered'}), 400
                user.email = result

            # Determine what changed for audit log
            changes = []
            if 'username' in data:
                changes.append(f"username to '{data['username']}'")
            if 'email' in data:
                changes.append(f"email to '{data['email']}'")
            if 'is_suspended' in data:
                changes.append(f"suspension status to {data['is_suspended']}")
                
            db.session.commit()
            
            # Create comprehensive audit log
            create_audit_log(
                action_type='user_update',
                description=f"Admin {get_current_user().username} updated user {user.username}",
                user=get_current_user(),
                target_type='user',
                target_id=str(user.id),
                details={
                    'target_username': user.username,
                    'changes_made': changes,
                    'updated_fields': list(data.keys())
                },
                severity='info',
                admin_action=True,
                category='admin'
            )
            
            return jsonify({'message': 'User updated successfully'})

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating user {user_id}: {str(e)}")
            return jsonify({'error': 'Failed to update user'}), 500

@api_route('/api/admin/clubs', methods=['POST'])
@admin_required
@limiter.limit("20 per hour")
def admin_create_club():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    # Check if club creation is enabled (admins can bypass this check)
    if not SystemSettings.is_club_creation_enabled():
        return jsonify({'error': 'Club creation is currently disabled.'}), 403

    data = request.get_json()
    step = data.get('step', 'initial')
    
    if step == 'verify_email':
        verification_code = data.get('verification_code', '').strip()
        leader_email = data.get('leader_email', '').strip()
        
        if not verification_code or not leader_email:
            return jsonify({'error': 'Verification code and email are required'}), 400
        
        # Verify the email code
        is_code_valid = airtable_service.verify_email_code(leader_email, verification_code)
        
        if is_code_valid:
            return jsonify({
                'success': True,
                'message': 'Email verification successful! You can now create the club.',
                'email_verified': True
            })
        else:
            return jsonify({'error': 'Invalid or expired verification code. Please check your email or request a new code.'}), 400
    
    elif step == 'send_verification':
        leader_email = data.get('leader_email', '').strip()
        
        if not leader_email:
            return jsonify({'error': 'Leader email is required'}), 400
        
        # Validate email format
        valid, email_result = validate_email(leader_email)
        if not valid:
            return jsonify({'error': email_result}), 400
        
        # Send verification code
        verification_code = airtable_service.send_email_verification(email_result)
        
        if verification_code:
            return jsonify({
                'success': True,
                'message': 'Verification code sent to the leader\'s email.',
                'verification_sent': True
            })
        else:
            return jsonify({'error': 'Failed to send verification code. Please try again.'}), 500
    
    # Regular club creation
    name = sanitize_string(data.get('name', '').strip(), max_length=100)
    filtered_name = filter_profanity_comprehensive(name)
    description = sanitize_string(data.get('description', '').strip(), max_length=1000)
    filtered_description = filter_profanity_comprehensive(description)
    location = sanitize_string(data.get('location', '').strip(), max_length=255)
    leader_email = data.get('leader_email', '').strip().lower()
    balance = data.get('balance', 0)
    email_verified = data.get('email_verified', False)

    if not name:
        return jsonify({'error': 'Club name is required'}), 400

    if not leader_email:
        return jsonify({'error': 'Leader email is required'}), 400
    
    if not email_verified:
        return jsonify({
            'error': 'Email verification required before creating club',
            'requires_verification': True,
            'verification_email': leader_email
        }), 403

    # Validate email format
    valid, email_result = validate_email(leader_email)
    if not valid:
        return jsonify({'error': email_result}), 400

    # Find the leader user
    leader = User.query.filter_by(email=email_result).first()
    if not leader:
        return jsonify({'error': 'User with that email not found'}), 404

    # Check if user is already leading a club
    existing_club = Club.query.filter_by(leader_id=leader.id).first()
    if existing_club:
        return jsonify({'error': f'User is already leading club: {existing_club.name}'}), 400

    # Check for duplicate club names
    existing_club = Club.query.filter_by(name=filtered_name).first()
    if existing_club:
        return jsonify({'error': f'A club with the name "{filtered_name}" already exists'}), 400

    try:
        # Create the club
        default_desc = f"Admin-created club: {filtered_name}"
        final_description = filtered_description or default_desc
        club = Club(
            name=filtered_name,
            description=final_description,
            location=location,
            leader_id=leader.id,
            balance=balance,
            sync_immune=True  # Admin-created clubs bypass intrusive connection popup by default
        )
        club.generate_join_code()

        db.session.add(club)
        db.session.commit()

        app.logger.info(f"Admin {current_user.username} created club {name} for user {leader.username} (email verified)")

        # Create comprehensive audit log
        create_audit_log(
            action_type='club_create',
            description=f"Admin {current_user.username} created club '{name}' for user {leader.username}",
            user=current_user,
            target_type='club',
            target_id=str(club.id),
            details={
                'club_name': name,
                'leader_username': leader.username,
                'leader_email': leader.email,
                'method': 'admin_creation'
            },
            severity='info',
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'message': 'Club linked successfully',
            'club': {
                'id': club.id,
                'name': club.name,
                'leader': leader.username,
                'join_code': club.join_code
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating club: {str(e)}")
        return jsonify({'error': 'Failed to create club'}), 500

@api_route('/api/admin/clubs/<int:club_id>/sync-immune', methods=['POST'])
@admin_required
@limiter.limit("50 per hour")
def toggle_club_sync_immune(club_id):
    """Toggle sync_immune status for a club"""
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    club = Club.query.get_or_404(club_id)
    data = request.get_json()

    if 'sync_immune' not in data:
        return jsonify({'error': 'sync_immune field is required'}), 400

    new_status = bool(data['sync_immune'])
    old_status = club.sync_immune

    try:
        club.sync_immune = new_status
        club.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        # Create audit log
        create_audit_log(
            action_type='club_update',
            description=f"Admin {current_user.username} {'enabled' if new_status else 'disabled'} sync_immune for club '{club.name}'",
            user=current_user,
            target_type='club',
            target_id=str(club.id),
            details={
                'club_name': club.name,
                'field': 'sync_immune',
                'old_value': old_status,
                'new_value': new_status
            },
            severity='info',
            category='club_management'
        )

        app.logger.info(f"Admin {current_user.username} toggled sync_immune for club {club.name} (ID: {club_id}): {old_status} -> {new_status}")

        return jsonify({
            'success': True,
            'message': f"Sync immune {'enabled' if new_status else 'disabled'} for {club.name}",
            'sync_immune': new_status
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error toggling sync_immune for club {club_id}: {str(e)}")
        return jsonify({'error': 'Failed to update club sync immune status'}), 500

@api_route('/api/admin/clubs/<int:club_id>', methods=['PUT', 'DELETE'])
@admin_required
@limiter.limit("50 per hour")
def admin_manage_club(club_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    club = Club.query.get_or_404(club_id)

    if request.method == 'DELETE':
        try:
            # Delete all related records in the correct order to avoid foreign key violations
            
            # Delete club-specific cosmetics and member cosmetic assignments
            MemberCosmetic.query.filter_by(club_id=club_id).delete()
            ClubCosmetic.query.filter_by(club_id=club_id).delete()
            
            # Delete transactions
            ClubTransaction.query.filter_by(club_id=club_id).delete()
            
            # Delete quest progress
            ClubQuestProgress.query.filter_by(club_id=club_id).delete()
            
            # Delete leaderboard exclusions
            LeaderboardExclusion.query.filter_by(club_id=club_id).delete()
            
            # Delete project submissions
            ProjectSubmission.query.filter_by(club_id=club_id).delete()
            
            # Delete slack settings
            ClubSlackSettings.query.filter_by(club_id=club_id).delete()
            
            # Delete gallery posts
            GalleryPost.query.filter_by(club_id=club_id).delete()
            
            # Delete club memberships
            ClubMembership.query.filter_by(club_id=club_id).delete()

            # Delete all other related data
            ClubPost.query.filter_by(club_id=club_id).delete()
            ClubAssignment.query.filter_by(club_id=club_id).delete()
            ClubMeeting.query.filter_by(club_id=club_id).delete()
            ClubResource.query.filter_by(club_id=club_id).delete()
            ClubProject.query.filter_by(club_id=club_id).delete()

            # Finally delete the club itself
            db.session.delete(club)
            db.session.commit()
            
            app.logger.info(f"Admin {current_user.username} successfully deleted club {club.name} (ID: {club_id})")
            return jsonify({'message': 'Club deleted successfully'})
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting club {club_id}: {str(e)}")
            return jsonify({'error': 'Failed to delete club. Please try again.'}), 500

    if request.method == 'PUT':
        data = request.get_json()

        if 'name' in data:
            filtered_name = filter_profanity_comprehensive(data['name'])
            # Check for duplicate club names (excluding current club)
            existing_club = Club.query.filter(Club.name == filtered_name, Club.id != club_id).first()
            if existing_club:
                return jsonify({'error': f'A club with the name "{filtered_name}" already exists'}), 400
            club.name = filtered_name
        if 'description' in data:
            filtered_description = filter_profanity_comprehensive(data['description'])
            club.description = filtered_description
        if 'location' in data:
            club.location = data['location']
        if 'balance' in data:
            old_balance_usd = float(club.balance)
            new_balance_usd = float(data['balance'])
            balance_change_usd = new_balance_usd - old_balance_usd
            
            if balance_change_usd != 0:
                # Update balance and create transaction
                club.balance = new_balance_usd
                club.tokens = int(new_balance_usd * 100)
                
                # Create transaction record for admin balance adjustment
                try:
                    success, tx_result = create_club_transaction(
                        club_id=club_id,
                        transaction_type='manual',
                        amount=int(balance_change_usd * 100),  # Convert to tokens
                        description=f"Admin balance adjustment: ${old_balance_usd:.2f} → ${new_balance_usd:.2f}",
                        reference_type='admin_adjustment',
                        created_by=current_user.id
                    )
                    
                    if success:
                        app.logger.info(f"Transaction recorded for admin balance adjustment: {int(balance_change_usd * 100)} tokens")
                    else:
                        app.logger.error(f"Failed to record transaction for admin balance adjustment: {tx_result}")
                except Exception as tx_error:
                    app.logger.error(f"Exception while recording admin balance adjustment transaction: {str(tx_error)}")

        db.session.commit()
        return jsonify({'message': 'Club updated successfully'})

@api_route('/api/admin/clubs/<int:club_id>/transfer-leadership', methods=['POST'])
@admin_required
@limiter.limit("20 per hour")
def admin_transfer_club_leadership(club_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    new_leader_id = data.get('new_leader_id')
    
    if not new_leader_id:
        return jsonify({'error': 'new_leader_id is required'}), 400

    # Get the club
    club = Club.query.get_or_404(club_id)
    
    # Get the new leader user
    new_leader = User.query.get(new_leader_id)
    if not new_leader:
        return jsonify({'error': 'New leader user not found'}), 404
    
    # Get current leader
    current_leader_id = club.leader_id
    current_leader = User.query.get(current_leader_id) if current_leader_id else None
    
    # Prevent transferring to the same user
    if current_leader_id == new_leader_id:
        return jsonify({'error': 'New leader must be different from current leader'}), 400

    try:
        # Update club leader
        old_leader_username = current_leader.username if current_leader else 'None'
        club.leader_id = new_leader_id
        
        # Handle new leader's membership
        existing_membership = ClubMembership.query.filter_by(
            user_id=new_leader_id,
            club_id=club_id
        ).first()
        
        if not existing_membership:
            # Add new leader as a member with leader role
            new_membership = ClubMembership(
                user_id=new_leader_id,
                club_id=club_id,
                role='leader',
                joined_at=datetime.utcnow()
            )
            db.session.add(new_membership)
        else:
            # Update existing membership to leader role
            existing_membership.role = 'leader'
        
        # Handle old leader's membership (downgrade to member if they have one)
        if current_leader_id:
            old_leader_membership = ClubMembership.query.filter_by(
                user_id=current_leader_id,
                club_id=club_id
            ).first()
            
            if old_leader_membership:
                old_leader_membership.role = 'member'
        
        db.session.commit()
        
        app.logger.info(f"Admin {current_user.username} transferred leadership of club '{club.name}' (ID: {club_id}) from {old_leader_username} to {new_leader.username}")
        
        return jsonify({
            'message': 'Club leadership transferred successfully',
            'club_id': club_id,
            'club_name': club.name,
            'old_leader': old_leader_username,
            'new_leader': new_leader.username
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error transferring leadership for club {club_id}: {str(e)}")
        return jsonify({'error': 'Failed to transfer leadership. Please try again.'}), 500

@api_route('/api/admin/users/search', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_search_users():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 50)), 200)  # Max 200 results

    if not query:
        return jsonify({'error': 'Search query required'}), 400

    # Search users by username, email, first name, or last name
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
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'is_reviewer': user.is_reviewer,
        'is_suspended': user.is_suspended,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'registration_ip': user.registration_ip,
        'last_login_ip': user.last_login_ip,
        'total_ips': len(user.get_all_ips()),
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    } for user in users]

    return jsonify({
        'users': users_data,
        'total': len(users_data)
    })

@api_route('/api/admin/clubs/search', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_search_clubs():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 50)), 200)  # Max 200 results

    if not query:
        return jsonify({'error': 'Search query required'}), 400

    # Search clubs by name, location, description, or leader info
    search_term = f"%{query}%"
    clubs = Club.query.join(User, Club.leader_id == User.id).filter(
        db.or_(
            Club.name.ilike(search_term),
            Club.location.ilike(search_term),
            Club.description.ilike(search_term),
            User.username.ilike(search_term),
            User.email.ilike(search_term)
        )
    ).limit(limit).all()

    clubs_data = [{
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': club.leader.username,
        'leader_email': club.leader.email,
        'member_count': len(club.members) + 1,  # +1 for leader
        'balance': float(club.balance),
        'created_at': club.created_at.isoformat() if club.created_at else None,
        'join_code': club.join_code
    } for club in clubs]

    return jsonify({'clubs': clubs_data})

@api_route('/api/admin/login-as-user/<int:user_id>', methods=['POST'])
@admin_required
@limiter.limit("5 per hour")  # More restrictive for this powerful action
def admin_login_as_user(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        app.logger.warning(f"Non-admin user {current_user.id} attempted to use admin login-as-user")
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)

    # Don't allow logging in as super admin or other admins
    if user.email == 'ethan@hackclub.com' or user.is_admin:
        app.logger.warning(f"Admin {current_user.id} attempted to login as admin user {user.id}")
        return jsonify({'error': 'Cannot login as admin users'}), 400

    # Additional security: log the action with full context
    app.logger.warning(f"ADMIN IMPERSONATION: Admin {current_user.username} (ID: {current_user.id}) logging in as user {user.username} (ID: {user.id}) from IP: {request.remote_addr}")

    # Log out current user and log in as the target user
    logout_user()
    login_user(user, remember=False)

    return jsonify({'message': f'Successfully logged in as {user.username}'})

@api_route('/api/admin/reset-password/<int:user_id>', methods=['POST'])
@admin_required
@limiter.limit("10 per hour")
def admin_reset_password(user_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long'}), 400

    # Don't allow resetting super admin password
    if user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot reset super admin password'}), 400

    user.set_password(new_password)
    db.session.commit()

    app.logger.info(f"Admin reset password for user {user.username} (ID: {user.id})")

    return jsonify({'message': 'Password reset successfully'})

@api_route('/api/admin/users/<int:user_id>/suspend', methods=['PUT'])
@admin_required
@limiter.limit("20 per hour")
def admin_suspend_user(user_id):
    current_user = get_current_user()
    if not (current_user.has_permission('users.suspend') or current_user.is_admin):
        return jsonify({'error': 'You do not have permission to suspend users'}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    # Don't allow suspending super admin
    if user.email == 'ethan@hackclub.com':
        return jsonify({'error': 'Cannot suspend super admin'}), 400

    new_suspension_status = data.get('is_suspended', not user.is_suspended)
    suspend_club_members = data.get('suspend_club_members', False)
    suspend_club = data.get('suspend_club', False)

    try:
        user.is_suspended = new_suspension_status
        
        actions_taken = []
        
        if new_suspension_status:  # Suspending user
            actions_taken.append(f"User {user.username} suspended")
            
            # Handle club leader suspension options
            led_clubs = Club.query.filter_by(leader_id=user.id).all()
            
            if led_clubs and (suspend_club_members or suspend_club):
                for club in led_clubs:
                    if suspend_club:
                        club.is_suspended = True
                        actions_taken.append(f"Club '{club.name}' suspended")
                    
                    if suspend_club_members:
                        # Suspend all club members
                        for membership in club.members:
                            if membership.user.email != 'ethan@hackclub.com':  # Don't suspend super admin
                                membership.user.is_suspended = True
                                actions_taken.append(f"Club member {membership.user.username} suspended")
        else:  # Unsuspending user
            actions_taken.append(f"User {user.username} unsuspended")
        
        db.session.commit()
        
        action_verb = "suspended" if new_suspension_status else "unsuspended"
        app.logger.info(f"Admin {current_user.username} {action_verb} user {user.username} (ID: {user.id}). Actions: {'; '.join(actions_taken)}")
        
        # Create comprehensive audit log
        create_audit_log(
            action_type='user_suspend' if new_suspension_status else 'user_unsuspend',
            description=f"Admin {current_user.username} {action_verb} user {user.username}",
            user=current_user,
            target_type='user',
            target_id=user.id,
            details={
                'target_user': user.username,
                'target_email': user.email,
                'suspension_status': new_suspension_status,
                'suspend_club_members': suspend_club_members,
                'suspend_club': suspend_club,
                'actions_taken': actions_taken,
                'reason': 'admin_action'
            },
            severity='warning' if new_suspension_status else 'info',
            admin_action=True,
            category='admin'
        )
        
        message = f"User {action_verb} successfully"
        if len(actions_taken) > 1:
            message += f". Additional actions: {'; '.join(actions_taken[1:])}"
        
        return jsonify({'message': message})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error suspending/unsuspending user {user_id}: {str(e)}")
        return jsonify({'error': 'Failed to update suspension status'}), 500

@api_route('/api/admin/sync-clubs-airtable', methods=['POST'])
@admin_required
@limiter.limit("5 per hour")
def admin_sync_clubs_airtable():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        result = airtable_service.sync_all_clubs_with_airtable()
        
        if result['success']:
            message = f"Sync completed: {result['created']} clubs created, {result['updated']} clubs updated from {result['total_airtable_clubs']} Airtable records"
            app.logger.info(f"Admin {current_user.username} synced clubs with Airtable: {message}")
            return jsonify({
                'success': True,
                'message': message,
                'stats': {
                    'created': result['created'],
                    'updated': result['updated'],
                    'total_airtable_clubs': result['total_airtable_clubs']
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error during sync')
            }), 500
            
    except Exception as e:
        app.logger.error(f"Error in admin club sync: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to sync clubs with Airtable'
        }), 500

@api_route('/api/admin/clubs/airtable-preview', methods=['GET'])
@admin_required
@limiter.limit("10 per hour")
def admin_preview_airtable_clubs():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_clubs = airtable_service.get_all_clubs_from_airtable()
        
        return jsonify({
            'success': True,
            'clubs': airtable_clubs[:50],  # Limit to first 50 for preview
            'total_count': len(airtable_clubs)
        })
        
    except Exception as e:
        app.logger.error(f"Error previewing Airtable clubs: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch clubs from Airtable'
        }), 500

# API Key Management
# Leaderboard Exclusion Management
@api_route('/api/admin/leaderboard/exclusions', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_get_leaderboard_exclusions():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        leaderboard_type = request.args.get('type', 'total_tokens')
        exclusions = db.session.query(LeaderboardExclusion).join(Club).join(User, LeaderboardExclusion.excluded_by == User.id).filter(
            LeaderboardExclusion.leaderboard_type == leaderboard_type
        ).all()
        
        exclusions_data = [{
            'id': exclusion.id,
            'club_id': exclusion.club_id,
            'club_name': exclusion.club.name,
            'club_location': exclusion.club.location,
            'leaderboard_type': exclusion.leaderboard_type,
            'excluded_by': exclusion.excluded_by_user.username,
            'excluded_at': exclusion.excluded_at.isoformat(),
            'reason': exclusion.reason
        } for exclusion in exclusions]
        
        return jsonify({
            'success': True,
            'exclusions': exclusions_data
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching leaderboard exclusions: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch exclusions'
        }), 500

@api_route('/api/admin/leaderboard/exclusions', methods=['POST'])
@admin_required
@limiter.limit("50 per hour")
def admin_add_leaderboard_exclusion():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        club_id = data.get('club_id')
        leaderboard_type = data.get('leaderboard_type', 'total_tokens')
        reason = data.get('reason', '')
        
        if not club_id:
            return jsonify({'error': 'Club ID is required'}), 400
            
        # Check if club exists
        club = Club.query.get(club_id)
        if not club:
            return jsonify({'error': 'Club not found'}), 404
            
        # Check if exclusion already exists
        existing = LeaderboardExclusion.query.filter_by(
            club_id=club_id,
            leaderboard_type=leaderboard_type
        ).first()
        
        if existing:
            return jsonify({'error': 'Club already excluded from this leaderboard'}), 409
            
        # Create new exclusion
        exclusion = LeaderboardExclusion(
            club_id=club_id,
            leaderboard_type=leaderboard_type,
            excluded_by=current_user.id,
            reason=reason
        )
        
        db.session.add(exclusion)
        db.session.commit()
        
        app.logger.info(f"Admin {current_user.username} excluded club {club.name} from {leaderboard_type} leaderboard")
        
        return jsonify({
            'success': True,
            'exclusion': {
                'id': exclusion.id,
                'club_id': exclusion.club_id,
                'club_name': club.name,
                'leaderboard_type': exclusion.leaderboard_type,
                'excluded_by': current_user.username,
                'excluded_at': exclusion.excluded_at.isoformat(),
                'reason': exclusion.reason
            }
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding leaderboard exclusion: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to add exclusion'
        }), 500

@api_route('/api/admin/leaderboard/exclusions/<int:exclusion_id>', methods=['DELETE'])
@admin_required
@limiter.limit("50 per hour")
def admin_remove_leaderboard_exclusion(exclusion_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        exclusion = LeaderboardExclusion.query.get(exclusion_id)
        if not exclusion:
            return jsonify({'error': 'Exclusion not found'}), 404
            
        club_name = exclusion.club.name
        leaderboard_type = exclusion.leaderboard_type
        
        db.session.delete(exclusion)
        db.session.commit()
        
        app.logger.info(f"Admin {current_user.username} removed exclusion for club {club_name} from {leaderboard_type} leaderboard")
        
        return jsonify({
            'success': True,
            'message': f'Exclusion removed for {club_name}'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error removing leaderboard exclusion: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to remove exclusion'
        }), 500

@api_route('/api/admin/api-keys', methods=['GET'])
@api_route('/api/admin/apikeys', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_get_api_keys():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    api_keys = APIKey.query.all()
    api_keys_data = [{
        'id': key.id,
        'name': key.name,
        'description': key.description,
        'user': key.user.username,
        'user_email': key.user.email,
        'scopes': key.get_scopes(),
        'is_active': key.is_active,
        'rate_limit': key.rate_limit,
        'created_at': key.created_at.isoformat() if key.created_at else None,
        'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None
    } for key in api_keys]

    return jsonify({'api_keys': api_keys_data})

@api_route('/api/admin/api-keys', methods=['POST'])
@api_route('/api/admin/apikeys', methods=['POST'])
@admin_required
@limiter.limit("20 per hour")
def admin_create_api_key():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    user_email = data.get('user_email', current_user.email).strip()
    rate_limit = data.get('rate_limit', 1000)
    scopes = data.get('scopes', [])

    if not name:
        return jsonify({'error': 'Name is required'}), 400

    if not scopes:
        return jsonify({'error': 'At least one scope is required'}), 400

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Validate scopes - map frontend values to backend values
    scope_mapping = {
        'read:clubs': 'clubs:read',
        'write:clubs': 'clubs:write', 
        'read:users': 'users:read',
        'write:users': 'users:write',
        'clubs:read': 'clubs:read',
        'clubs:write': 'clubs:write',
        'users:read': 'users:read',
        'projects:read': 'projects:read',
        'assignments:read': 'assignments:read',
        'meetings:read': 'meetings:read',
        'analytics:read': 'analytics:read'
    }
    
    # Convert scopes using mapping
    converted_scopes = []
    for scope in scopes:
        if scope in scope_mapping:
            converted_scopes.append(scope_mapping[scope])
        else:
            return jsonify({'error': f'Invalid scope: {scope}'}), 400

    api_key = APIKey(
        name=name,
        description=description,
        user_id=user.id,
        rate_limit=rate_limit
    )
    api_key.generate_key()
    api_key.set_scopes(converted_scopes)

    db.session.add(api_key)
    db.session.commit()

    return jsonify({
        'message': 'API key created successfully',
        'api_key': api_key.key
    })

@api_route('/api/admin/api-keys/<int:key_id>', methods=['PUT', 'DELETE'])
@admin_required
@limiter.limit("50 per hour")
def admin_manage_api_key(key_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    api_key = APIKey.query.get_or_404(key_id)

    if request.method == 'DELETE':
        db.session.delete(api_key)
        db.session.commit()
        return jsonify({'message': 'API key deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            api_key.name = data['name']
        if 'description' in data:
            api_key.description = data['description']
        if 'is_active' in data:
            api_key.is_active = bool(data['is_active'])
        if 'rate_limit' in data:
            api_key.rate_limit = int(data['rate_limit'])
        if 'scopes' in data:
            api_key.set_scopes(data['scopes'])

        db.session.commit()
        return jsonify({'message': 'API key updated successfully'})

# OAuth Application Management
@api_route('/api/admin/oauth-applications', methods=['GET'])
@api_route('/api/admin/oauthapps', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_get_oauth_apps():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    oauth_apps = OAuthApplication.query.all()
    oauth_apps_data = [{
        'id': app.id,
        'name': app.name,
        'description': app.description,
        'client_id': app.client_id,
        'user': app.user.username,
        'user_email': app.user.email,
        'redirect_uris': app.get_redirect_uris(),
        'scopes': app.get_scopes(),
        'is_active': app.is_active,
        'created_at': app.created_at.isoformat() if app.created_at else None
    } for app in oauth_apps]

    return jsonify({'oauth_apps': oauth_apps_data, 'oauth_applications': oauth_apps_data})

@api_route('/api/admin/oauth-applications', methods=['POST'])
@api_route('/api/admin/oauthapps', methods=['POST'])
@admin_required
@limiter.limit("20 per hour")
def admin_create_oauth_app():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    user_email = data.get('user_email', current_user.email).strip()
    redirect_uris = data.get('redirect_uris', [])
    scopes = data.get('scopes', [])

    if not name:
        return jsonify({'error':'Name is required'}), 400

    if not redirect_uris:
        return jsonify({'error': 'At least one redirect URI is required'}), 400

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Validate scopes
    valid_scopes = ['clubs:read', 'clubs:write', 'users:read', 'projects:read', 
                   'assignments:read', 'meetings:read', 'analytics:read']
    invalid_scopes = [s for s in scopes if s not in valid_scopes]
    if invalid_scopes:
        return jsonify({'error': f'Invalid scopes: {", ".join(invalid_scopes)}'}), 400

    oauth_app = OAuthApplication(
        name=name,
        description=description,
        user_id=user.id
    )
    oauth_app.generate_credentials()
    oauth_app.set_redirect_uris(redirect_uris)
    oauth_app.set_scopes(scopes)

    db.session.add(oauth_app)
    db.session.commit()

    return jsonify({
        'message': 'OAuth application created successfully',
        'client_id': oauth_app.client_id,
        'client_secret': oauth_app.client_secret
    })

@api_route('/api/admin/oauth-applications/<int:app_id>', methods=['PUT', 'DELETE'])
@admin_required
@limiter.limit("50 per hour")
def admin_manage_oauth_app(app_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    oauth_app = OAuthApplication.query.get_or_404(app_id)

    if request.method == 'DELETE':
        # Delete related tokens and authorization codes
        OAuthToken.query.filter_by(application_id=app_id).delete()
        OAuthAuthorizationCode.query.filter_by(application_id=app_id).delete()

        db.session.delete(oauth_app)
        db.session.commit()
        return jsonify({'message': 'OAuth application deleted successfully'})

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            oauth_app.name = data['name']
        if 'description' in data:
            oauth_app.description = data['description']
        if 'is_active' in data:
            oauth_app.is_active = bool(data['is_active'])
        if 'redirect_uris' in data:
            oauth_app.set_redirect_uris(data['redirect_uris'])
        if 'scopes' in data:
            oauth_app.set_scopes(data['scopes'])

        db.session.commit()
        return jsonify({'message': 'OAuth application updated successfully'})

# Admin Pizza Grant Management
@api_route('/api/admin/pizza-grants', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def admin_get_pizza_grants():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_service = AirtableService()
        submissions = airtable_service.get_pizza_grant_submissions()
        return jsonify({'submissions': submissions})
    except Exception as e:
        app.logger.error(f"Error fetching pizza grant submissions: {str(e)}")
        return jsonify({'error': 'Failed to fetch submissions'}), 500

@api_route('/api/admin/pizza-grants/review', methods=['POST'])
@admin_required
@limiter.limit("50 per hour")
def admin_review_pizza_grant():
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    submission_id = data.get('submission_id')
    action = data.get('action')  # 'approve' or 'reject'

    if not submission_id or not action:
        return jsonify({'error': 'submission_id and action are required'}), 400

    if action not in ['approve', 'reject']:
        return jsonify({'error': 'action must be approve or reject'}), 400

    try:
        airtable_service = AirtableService()
        
        # If approving, we need to add funds to the club balance
        if action == 'approve':
            # Get the full submission with all fields including email and grant amount
            submissions = airtable_service.get_pizza_grant_submissions()
            full_submission = next((s for s in submissions if s['id'] == submission_id), None)
            
            if not full_submission:
                return jsonify({'error': 'Submission not found'}), 404
            
            # Check if already approved to prevent double-payment
            current_status = full_submission.get('status', '').lower()
            if current_status == 'approved':
                return jsonify({'error': 'Grant has already been approved'}), 400
            
            grant_amount_raw = full_submission.get('grant_amount')
            submitter_email = full_submission.get('email')
            
            if not submitter_email:
                return jsonify({'error': 'Submitter email not found'}), 400
            
            # Parse grant amount - handle various formats
            if not grant_amount_raw:
                return jsonify({'error': 'Grant amount not found'}), 400
            
            try:
                # Convert to string and clean up
                grant_amount_str = str(grant_amount_raw).strip()
                
                # Remove currency symbols and common formatting
                import re
                grant_amount_str = re.sub(r'[^\d.-]', '', grant_amount_str)
                
                if not grant_amount_str:
                    return jsonify({'error': 'Grant amount is empty after cleaning'}), 400
                
                from decimal import Decimal
                grant_amount = Decimal(grant_amount_str)
                
                if grant_amount <= 0:
                    return jsonify({'error': 'Grant amount must be positive'}), 400
                    
            except (ValueError, TypeError) as e:
                app.logger.error(f"Error parsing grant amount '{grant_amount_raw}': {str(e)}")
                return jsonify({'error': f'Invalid grant amount format: {grant_amount_raw}'}), 400
            
            # Find the user and their club
            submitter = User.query.filter_by(email=submitter_email).first()
            if not submitter:
                return jsonify({'error': 'Submitter not found in system'}), 404
            
            # Check if user leads a club or is a member of one
            club = None
            if submitter.led_clubs:
                club = submitter.led_clubs[0]  # User leads a club
            elif submitter.clubs:
                club = submitter.clubs[0]  # User is a member of a club
            
            if not club:
                return jsonify({'error': 'User is not associated with any club'}), 404
            
            # Create transaction record for the grant (this will update balance automatically)
            try:
                success, tx_result = create_club_transaction(
                    club_id=club.id,
                    transaction_type='grant',
                    amount=int(grant_amount * 100),  # Convert to tokens (positive for credit)
                    description=f"Grant approved for submission {submission_id}",
                    reference_id=submission_id,
                    reference_type='grant_approval',
                    created_by=current_user.id
                )
                
                if success:
                    app.logger.info(f"Transaction recorded for grant: {int(grant_amount * 100)} tokens credited")
                else:
                    app.logger.error(f"Failed to record transaction for grant: {tx_result}")
            except Exception as tx_error:
                app.logger.error(f"Exception while recording grant transaction: {str(tx_error)}")
            
            app.logger.info(f"Added ${grant_amount} to club '{club.name}' (ID: {club.id}) for approved grant {submission_id}")
        
        # Update the submission status in Airtable
        result = airtable_service.update_submission_status(submission_id, action)
        
        if result:
            if action == 'approve':
                return jsonify({
                    'message': f'Grant approved successfully and {int(float(grant_amount) * 100)} tokens added to {club.name}\'s balance'
                })
            else:
                return jsonify({'message': f'Grant {action}d successfully'})
        else:
            return jsonify({'error': f'Failed to update grant status in Airtable'}), 500
    except Exception as e:
        app.logger.error(f"Error {action}ing submission {submission_id}: {str(e)}")
        return jsonify({'error': f'Failed to {action} grant'}), 500

@api_route('/api/admin/pizza-grants/<string:submission_id>', methods=['DELETE'])
@admin_required
@limiter.limit("50 per hour")
def admin_delete_pizza_grant(submission_id):
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        airtable_service = AirtableService()
        result = airtable_service.delete_submission(submission_id)
        
        if result:
            return jsonify({'message': 'Submission deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete submission'}), 500
    except Exception as e:
        app.logger.error(f"Error deleting submission {submission_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete submission'}), 500

@api_route('/api/admin/clubs/allocate-tokens', methods=['POST'])
@admin_required
@limiter.limit("5 per hour")
def admin_allocate_tokens_to_existing_clubs():
    """Allocate 400 tokens to all existing clubs with Airtable records"""
    current_user = get_current_user()
    
    try:
        # Get all clubs with airtable_data (regardless of current token balance)
        clubs_to_allocate = Club.query.filter(
            Club.airtable_data.isnot(None)
        ).all()
        
        allocated_count = 0
        failed_count = 0
        results = []
        
        for club in clubs_to_allocate:
            try:
                # This allocation has been disabled
                success = True
                result = "Token allocation disabled"
                
                if success:
                    allocated_count += 1
                    results.append({
                        'club_id': club.id,
                        'club_name': club.name,
                        'status': 'success',
                        'message': 'Club processed (token allocation disabled)'
                    })
                    
                    
                    # Update Airtable to mark club as onboarded to dashboard
                    try:
                        airtable_data = club.get_airtable_data()
                        if airtable_data and airtable_data.get('airtable_id'):
                            airtable_update_url = f'https://api.airtable.com/v0/{airtable_service.clubs_base_id}/{airtable_service.clubs_table_id}/{airtable_data["airtable_id"]}'
                            airtable_update_data = {
                                'fields': {
                                    'Onboarded to Dashboard': True
                                }
                            }
                            
                            response = requests.patch(airtable_update_url, 
                                                    headers=airtable_service.headers, 
                                                    json=airtable_update_data,
                                                    timeout=30)
                            
                            if response.status_code != 200:
                                app.logger.error(f"Failed to update Airtable onboarded status for club {club.id}: {response.text}")
                                
                    except Exception as e:
                        app.logger.error(f"Error updating Airtable onboarded status for club {club.id}: {str(e)}")
                        
                else:
                    failed_count += 1
                    results.append({
                        'club_id': club.id,
                        'club_name': club.name,
                        'status': 'failed',
                        'message': f'Failed to allocate tokens: {result}'
                    })
                    
            except Exception as e:
                failed_count += 1
                results.append({
                    'club_id': club.id,
                    'club_name': club.name,
                    'status': 'failed',
                    'message': f'Error: {str(e)}'
                })
                
        # Log the allocation action
        app.logger.info(f"Admin {current_user.username} allocated tokens to {allocated_count} clubs, {failed_count} failed")
        
        return jsonify({
            'success': True,
            'message': f'Token allocation completed. {allocated_count} clubs successful, {failed_count} failed.',
            'allocated_count': allocated_count,
            'failed_count': failed_count,
            'results': results
        })
        
    except Exception as e:
        app.logger.error(f"Error in admin token allocation: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Public API Endpoints
@api_route('/api/v1/clubs', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("100 per hour")
def api_get_clubs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '').strip()
    all_clubs = request.args.get('all', '').lower() == 'true'

    query = Club.query

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Club.name.ilike(search_term),
                Club.location.ilike(search_term),
                Club.description.ilike(search_term)
            )
        )

    if all_clubs:
        # Return all clubs without pagination
        clubs = query.all()
        clubs_data = []
        for club in clubs:
            airtable_data = club.get_airtable_data()
            clubs_data.append({
                'id': club.id,
                'name': club.name,
                'description': club.description,
                'location': club.location,
                'leader': {
                    'id': club.leader.id,
                    'username': club.leader.username,
                    'email': club.leader.email
                },
                'member_count': len(club.members) + 1,
                'balance': float(club.balance),
                'created_at': club.created_at.isoformat() if club.created_at else None,
                'updated_at': club.updated_at.isoformat() if club.updated_at else None,
                'airtable_data': airtable_data
            })

        return jsonify({
            'clubs': clubs_data,
            'total': len(clubs_data)
        })
    else:
        # Use pagination with no upper limit on per_page
        clubs_paginated = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )

        clubs_data = []
        for club in clubs_paginated.items:
            airtable_data = club.get_airtable_data()
            clubs_data.append({
                'id': club.id,
                'name': club.name,
                'description': club.description,
                'location': club.location,
                'leader': {
                    'id': club.leader.id,
                    'username': club.leader.username,
                    'email': club.leader.email
                },
                'member_count': len(club.members) + 1,
                'balance': float(club.balance),
                'created_at': club.created_at.isoformat() if club.created_at else None,
                'updated_at': club.updated_at.isoformat() if club.updated_at else None,
                'airtable_data': airtable_data
            })

        return jsonify({
            'clubs': clubs_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': clubs_paginated.total,
                'pages': clubs_paginated.pages,
                'has_next': clubs_paginated.has_next,
                'has_prev': clubs_paginated.has_prev
            }
        })

@api_route('/api/v1/clubs/<int:club_id>', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club(club_id):
    club = Club.query.get(club_id)

    if not club:
        # Try Airtable lookup as fallback
        try:
            # Search for club in Airtable
            airtable_url = f'https://api.airtable.com/v0/{airtable_service.clubs_base_id}/{urllib.parse.quote(airtable_service.clubs_table_name)}'
            headers = {'Authorization': f'Bearer {airtable_service.api_token}'}
            params = {'filterByFormula': f'{{ID}} = "{club_id}"'}

            response = requests.get(airtable_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                if records:
                    record = records[0]
                    fields = record.get('fields', {})
                    return jsonify({
                        'club': {
                            'id': club_id,
                            'name': fields.get('Club Name', 'Unknown Club'),
                            'description': 'Club found in Hack Club directory',
                            'location': fields.get('Location', ''),
                            'leader': {
                                'email': fields.get("Current Leaders' Emails", '').split(',')[0].strip()
                            },
                            'member_count': 0,
                            'balance': 0.0,
                            'created_at': None,
                            'source': 'airtable',
                            'airtable_data': {
                                'status': fields.get('Status', ''),
                                'meeting_day': fields.get('Meeting Day', ''),
                                'meeting_time': fields.get('Meeting Time', ''),
                                'website': fields.get('Website', ''),
                                'country': fields.get('Country', ''),
                                'region': fields.get('Region', ''),
                            }
                        }
                    })
        except:
            pass

        return jsonify({'error': 'Club not found'}), 404

    airtable_data = club.get_airtable_data()
    
    club_data = {
        'id': club.id,
        'name': club.name,
        'description': club.description,
        'location': club.location,
        'leader': {
            'id': club.leader.id,
            'username': club.leader.username,
            'email': club.leader.email
        },
        'member_count': len(club.members) + 1,
        'balance': float(club.balance),
        'join_code': club.join_code,
        'created_at': club.created_at.isoformat() if club.created_at else None,
        'updated_at': club.updated_at.isoformat() if club.updated_at else None,
        'source': 'database',
        'airtable_data': airtable_data
    }

    return jsonify({'club': club_data})

@api_route('/api/v1/clubs/<int:club_id>/members', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_get_club_members(club_id):
    club = Club.query.get_or_404(club_id)

    members_data = []

    # Add all members from membership records (includes leaders with correct roles)
    for membership in club.members:
        members_data.append({
            'id': membership.user.id,
            'username': membership.user.username,
            'email': membership.user.email,
            'role': membership.role,
            'joined_at': membership.joined_at.isoformat() if membership.joined_at else None
        })

    # Sort by role priority (leader first, then co-leader, then members)
    role_priority = {'leader': 1, 'co-leader': 2, 'member': 3}
    members_data.sort(key=lambda x: (role_priority.get(x['role'], 4), x['username'].lower()))

    return jsonify({'members': members_data})

@api_route('/api/v1/clubs/<int:club_id>/projects', methods=['GET'])
@api_key_required(['projects:read'])
@limiter.limit("200 per hour")
def api_get_club_projects(club_id):
    club = Club.query.get_or_404(club_id)

    projects = ClubProject.query.filter_by(club_id=club_id).order_by(ClubProject.updated_at.desc()).all()

    projects_data = [{
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'url': project.url,
        'github_url': project.github_url,
        'featured': project.featured,
        'author': {
            'id': project.user.id,
            'username': project.user.username
        },
        'created_at': project.created_at.isoformat() if project.created_at else None,
        'updated_at': project.updated_at.isoformat() if project.updated_at else None
    } for project in projects]

    return jsonify({'projects': projects_data})

@api_route('/api/v1/users/<int:user_id>', methods=['GET'])
@api_key_required(['users:read'])
@limiter.limit("200 per hour")
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)

    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'clubs_led': len(user.led_clubs),
        'clubs_joined': len(user.club_memberships)
    }

    return jsonify({'user': user_data})

@api_route('/api/v1/clubs/search', methods=['GET'])
@api_key_required(['clubs:read'])
@limiter.limit("200 per hour")
def api_search_clubs():
    """Search clubs by name, location, or description. Returns basic info to help find club IDs."""
    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 20)), 100)  # Max 100 results
    
    if not query:
        return jsonify({
            'error': 'Search query required',
            'message': 'Use ?q=search_term to search for clubs',
            'example': '/api/v1/clubs/search?q=tech'
        }), 400
    
    # Search clubs by name, location, or description
    search_term = f"%{query}%"
    clubs = Club.query.filter(
        db.or_(
            Club.name.ilike(search_term),
            Club.location.ilike(search_term),
            Club.description.ilike(search_term)
        )
    ).limit(limit).all()
    
    clubs_data = []
    for club in clubs:
        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'location': club.location,
            'description': club.description[:100] + ('...' if len(club.description or '') > 100 else ''),
            'leader': {
                'id': club.leader.id,
                'username': club.leader.username,
                'email': club.leader.email
            },
            'member_count': len(club.members) + 1,
            'created_at': club.created_at.isoformat() if club.created_at else None
        })
    
    return jsonify({
        'clubs': clubs_data,
        'total_results': len(clubs_data),
        'search_query': query,
        'limit': limit
    })

@api_route('/api/v1/users/search', methods=['GET'])
@api_key_required(['users:read'])
@limiter.limit("200 per hour")
def api_search_users():
    """Search users by username, email, or name. Returns basic info to help find user IDs."""
    query = request.args.get('q', '').strip()
    limit = min(int(request.args.get('limit', 20)), 100)  # Max 100 results
    
    if not query:
        return jsonify({
            'error': 'Search query required',
            'message': 'Use ?q=search_term to search for users',
            'example': '/api/v1/users/search?q=john'
        }), 400
    
    # Search users by username, email, first name, or last name
    search_term = f"%{query}%"
    users = User.query.filter(
        db.or_(
            User.username.ilike(search_term),
            User.email.ilike(search_term),
            User.first_name.ilike(search_term),
            User.last_name.ilike(search_term)
        )
    ).limit(limit).all()
    
    users_data = []
    for user in users:
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': full_name if full_name else None,
            'is_admin': user.is_admin,
            'clubs_led': len(user.led_clubs),
            'clubs_joined': len(user.club_memberships),
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })
    
    return jsonify({
        'users': users_data,
        'total_results': len(users_data),
        'search_query': query,
        'limit': limit
    })

@api_route('/api/v1/analytics/overview', methods=['GET'])
@api_key_required(['analytics:read'])
@limiter.limit("100 per hour")
def api_get_analytics():
    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()
    total_meetings = ClubMeeting.query.count()
    total_projects = ClubProject.query.count()

    # Calculate 30-day stats
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    new_users_30d = User.query.filter(User.created_at >= thirty_days_ago).count()
    new_clubs_30d = Club.query.filter(Club.created_at >= thirty_days_ago).count()
    active_users_30d = User.query.filter(User.last_login >= thirty_days_ago).count()

    analytics_data = {
        'totals': {
            'users': total_users,
            'clubs': total_clubs,
            'posts': total_posts,
            'assignments': total_assignments,
            'meetings': total_meetings,
            'projects': total_projects
        },
        'recent': {
            'new_users_30d': new_users_30d,
            'new_clubs_30d': new_clubs_30d,
            'active_users_30d': active_users_30d
        }
    }

    return jsonify({'analytics': analytics_data})

@api_route('/api/v1/admin/clubs/<int:club_id>/tokens/grant', methods=['POST'])
@api_key_required(['clubs:write'])
@limiter.limit("50 per hour")
def api_grant_tokens(club_id):
    """Grant tokens to a club (Admin API)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        amount = data.get('amount')
        description = data.get('description', '')
        admin_note = data.get('admin_note', '')

        # Validate input
        if amount is None:
            return jsonify({'error': 'Amount is required'}), 400
        
        try:
            amount = int(amount)
        except (ValueError, TypeError):
            return jsonify({'error': 'Amount must be an integer'}), 400

        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        if amount > 100000:  # 1000 USD limit
            return jsonify({'error': 'Amount cannot exceed 100,000 tokens (1000 USD)'}), 400

        # Get club
        club = Club.query.get(club_id)
        if not club:
            return jsonify({'error': 'Club not found'}), 404

        # Create transaction
        success, result = create_club_transaction(
            club_id=club_id,
            transaction_type='grant',
            amount=amount,
            description=f"Admin token grant: {description}" if description else "Admin token grant",
            reference_type='admin_grant',
            created_by=None  # API key doesn't have user context
        )

        if not success:
            return jsonify({'error': f'Failed to grant tokens: {result}'}), 500

        # Create audit log
        create_audit_log(
            action_type='admin_tokens_grant',
            description=f"API granted {amount} tokens to club '{club.name}' (ID: {club_id})",
            user=None,
            target_type='club',
            target_id=str(club_id),
            details={
                'amount': amount,
                'club_name': club.name,
                'description': description,
                'admin_note': admin_note,
                'new_balance': club.tokens,
                'api_key_used': True
            },
            severity='info',
            admin_action=True,
            category='finance'
        )

        app.logger.info(f"API granted {amount} tokens to club '{club.name}' (ID: {club_id}). New balance: {club.tokens}")

        return jsonify({
            'success': True,
            'message': f'Granted {amount} tokens to {club.name}',
            'club_id': club_id,
            'club_name': club.name,
            'amount_granted': amount,
            'new_balance': club.tokens,
            'transaction_id': result.id
        })

    except Exception as e:
        app.logger.error(f"Error granting tokens to club {club_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/v1/admin/clubs/<int:club_id>/tokens/remove', methods=['POST'])
@api_key_required(['clubs:write'])
@limiter.limit("50 per hour")
def api_remove_tokens(club_id):
    """Remove tokens from a club (Admin API)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body required'}), 400

        amount = data.get('amount')
        description = data.get('description', '')
        admin_note = data.get('admin_note', '')
        force = data.get('force', False)

        # Validate input
        if amount is None:
            return jsonify({'error': 'Amount is required'}), 400
        
        try:
            amount = int(amount)
        except (ValueError, TypeError):
            return jsonify({'error': 'Amount must be an integer'}), 400

        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        # Get club
        club = Club.query.get(club_id)
        if not club:
            return jsonify({'error': 'Club not found'}), 404

        # Check if club has sufficient balance (unless force is true)
        if not force and club.tokens < amount:
            return jsonify({
                'error': 'Insufficient balance',
                'current_balance': club.tokens,
                'requested_amount': amount,
                'message': 'Use force=true to allow negative balance'
            }), 400

        # Create transaction (negative amount for debit)
        success, result = create_club_transaction(
            club_id=club_id,
            transaction_type='debit',
            amount=-amount,  # Negative for removal
            description=f"Admin token removal: {description}" if description else "Admin token removal",
            reference_type='admin_removal',
            created_by=None  # API key doesn't have user context
        )

        if not success:
            return jsonify({'error': f'Failed to remove tokens: {result}'}), 500

        # Create audit log
        create_audit_log(
            action_type='admin_tokens_remove',
            description=f"API removed {amount} tokens from club '{club.name}' (ID: {club_id})",
            user=None,
            target_type='club',
            target_id=str(club_id),
            details={
                'amount': amount,
                'club_name': club.name,
                'description': description,
                'admin_note': admin_note,
                'new_balance': club.tokens,
                'force_used': force,
                'api_key_used': True
            },
            severity='warning',
            admin_action=True,
            category='finance'
        )

        app.logger.warning(f"API removed {amount} tokens from club '{club.name}' (ID: {club_id}). New balance: {club.tokens}")

        return jsonify({
            'success': True,
            'message': f'Removed {amount} tokens from {club.name}',
            'club_id': club_id,
            'club_name': club.name,
            'amount_removed': amount,
            'new_balance': club.tokens,
            'transaction_id': result.id
        })

    except Exception as e:
        app.logger.error(f"Error removing tokens from club {club_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# OAuth Endpoints
@app.route('/oauth/authorize', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def oauth_authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')

    # Validate required parameters
    if not client_id:
        return jsonify({
            'error': 'Missing client_id parameter',
            'error_code': 'MISSING_CLIENT_ID',
            'message': 'The client_id parameter is required for OAuth authorization',
            'how_to_fix': 'Include client_id in your authorization URL query parameters'
        }), 400

    if not redirect_uri:
        return jsonify({
            'error': 'Missing redirect_uri parameter',
            'error_code': 'MISSING_REDIRECT_URI',
            'message': 'The redirect_uri parameter is required for OAuth authorization',
            'how_to_fix': 'Include redirect_uri in your authorization URL query parameters'
        }), 400

    if not response_type or response_type != 'code':
        return jsonify({
            'error': 'Invalid response_type parameter',
            'error_code': 'INVALID_RESPONSE_TYPE',
            'message': 'Only "code" response_type is supported for OAuth authorization',
            'received': response_type,
            'how_to_fix': 'Set response_type=code in your authorization URL'
        }), 400

    try:
        oauth_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
    except Exception as e:
        app.logger.error(f"Database error in oauth_authorize: {e}")
        try:
            db.session.rollback()
            oauth_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
        except Exception as e2:
            app.logger.error(f"Database retry failed in oauth_authorize: {e2}")
            return jsonify({
                'error': 'Database connection error',
                'error_code': 'DATABASE_ERROR',
                'message': 'Temporary database issue, please try again',
                'how_to_fix': 'Wait a moment and retry your request'
            }), 500
    
    if not oauth_app:
        # Check if client exists but is inactive
        inactive_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=False).first()
        if inactive_app:
            return jsonify({
                'error': 'OAuth application disabled',
                'error_code': 'CLIENT_DISABLED',
                'message': 'This OAuth application has been disabled',
                'how_to_fix': 'Contact the application administrator to reactivate the OAuth application'
            }), 400
        else:
            return jsonify({
                'error': 'Invalid client_id',
                'error_code': 'INVALID_CLIENT_ID',
                'message': 'The provided client_id does not exist',
                'how_to_fix': 'Verify your client_id is correct or register a new OAuth application'
            }), 400

    # Check if redirect_uri is allowed
    allowed_redirect_uris = oauth_app.get_redirect_uris()
    if redirect_uri not in allowed_redirect_uris:
        return jsonify({
            'error': 'Invalid redirect_uri',
            'error_code': 'INVALID_REDIRECT_URI',
            'message': 'The redirect_uri is not registered for this OAuth application',
            'provided_uri': redirect_uri,
            'allowed_uris': allowed_redirect_uris,
            'how_to_fix': 'Use one of the registered redirect URIs or update your OAuth application configuration'
        }), 400

    # Check if user is authenticated
    if not is_authenticated():
        # Store OAuth params in session and redirect to login
        session['oauth_params'] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'scope': scope,
            'state': state
        }
        return redirect(url_for('login'))

    # Validate requested scopes
    requested_scopes = scope.split() if scope else []
    allowed_scopes = oauth_app.get_scopes()
    invalid_scopes = [s for s in requested_scopes if s not in allowed_scopes]
    if invalid_scopes:
        return jsonify({
            'error': 'Invalid scopes requested',
            'error_code': 'INVALID_SCOPES',
            'message': f'The following scopes are not allowed for this application: {", ".join(invalid_scopes)}',
            'invalid_scopes': invalid_scopes,
            'allowed_scopes': allowed_scopes,
            'how_to_fix': 'Request only scopes that are configured for this OAuth application'
        }), 400

    current_user = get_current_user()

    # Handle POST request (user approved/denied)
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'deny':
            # Redirect back with error
            error_url = f"{redirect_uri}?error=access_denied"
            if state:
                error_url += f"&state={state}"
            return redirect(error_url)
        
        elif action == 'approve':
            # Always require identity verification to get the most up-to-date information
            # Store OAuth params and redirect to identity verification
            session['pending_oauth'] = {
                'application_id': oauth_app.id,
                'redirect_uri': redirect_uri,
                'state': state,
                'scopes': requested_scopes
            }
            
            # Get identity authorization URL
            identity_redirect_uri = url_for('hackclub_identity_callback', _external=True, _scheme='https')
            identity_state = secrets.token_urlsafe(32)
            session['hackclub_identity_state'] = identity_state
            
            identity_auth_url = hackclub_identity_service.get_auth_url(identity_redirect_uri, identity_state)
            return redirect(identity_auth_url)

    # Show consent page
    scope_descriptions = {
        'clubs:read': 'View your clubs and club information',
        'clubs:write': 'Create and manage clubs on your behalf',
        'users:read': 'View your profile information',
        'projects:read': 'View your projects and club projects',
        'assignments:read': 'View club assignments',
        'meetings:read': 'View club meetings',
        'analytics:read': 'View analytics and statistics'
    }

    scopes_with_descriptions = []
    for scope_name in requested_scopes:
        scopes_with_descriptions.append({
            'name': scope_name,
            'description': scope_descriptions.get(scope_name, f'Access {scope_name}')
        })

    # Check if mobile device
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    # Check for mobile parameter override
    force_mobile = request.args.get('mobile', '').lower() == 'true'
    force_desktop = request.args.get('desktop', '').lower() == 'true'
    
    # Determine template to use
    template_name = 'oauth_consent_mobile.html' if (is_mobile or force_mobile) and not force_desktop else 'oauth_consent.html'

    return render_template(template_name, 
                         app=oauth_app, 
                         scopes=scopes_with_descriptions,
                         client_id=client_id,
                         redirect_uri=redirect_uri,
                         response_type=response_type,
                         scope=scope,
                         state=state)

@app.route('/oauth/token', methods=['POST'])
@limiter.limit("60 per minute")
def oauth_token():
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')

    if not grant_type:
        return jsonify({
            'error': 'Missing grant_type parameter',
            'error_code': 'MISSING_GRANT_TYPE',
            'message': 'The grant_type parameter is required',
            'how_to_fix': 'Include grant_type=authorization_code in your POST request'
        }), 400

    if grant_type != 'authorization_code':
        return jsonify({
            'error': 'Unsupported grant_type',
            'error_code': 'UNSUPPORTED_GRANT_TYPE',
            'message': 'Only "authorization_code" grant type is supported',
            'received': grant_type,
            'supported_types': ['authorization_code'],
            'how_to_fix': 'Use grant_type=authorization_code in your request'
        }), 400

    missing_params = []
    if not client_id:
        missing_params.append('client_id')
    if not client_secret:
        missing_params.append('client_secret')
    if not code:
        missing_params.append('code')
    if not redirect_uri:
        missing_params.append('redirect_uri')

    if missing_params:
        return jsonify({
            'error': 'Missing required parameters',
            'error_code': 'MISSING_PARAMETERS',
            'message': f'The following parameters are required: {", ".join(missing_params)}',
            'missing_parameters': missing_params,
            'how_to_fix': 'Include all required parameters in your POST request body'
        }), 400

    # Verify client credentials
    oauth_app = OAuthApplication.query.filter_by(client_id=client_id, is_active=True).first()
    
    if not oauth_app:
        return jsonify({
            'error': 'Invalid client_id',
            'error_code': 'INVALID_CLIENT_ID',
            'message': 'The provided client_id does not exist or is disabled',
            'how_to_fix': 'Verify your client_id is correct and the OAuth application is active'
        }), 401

    if oauth_app.client_secret != client_secret:
        return jsonify({
            'error': 'Invalid client credentials',
            'error_code': 'INVALID_CLIENT_SECRET',
            'message': 'The provided client_secret is incorrect',
            'how_to_fix': 'Verify your client_secret is correct'
        }), 401

    # Verify authorization code
    auth_code = OAuthAuthorizationCode.query.filter_by(
        code=code,
        application_id=oauth_app.id,
        redirect_uri=redirect_uri,
        used=False
    ).first()

    if not auth_code:
        # Check for more specific error cases
        used_code = OAuthAuthorizationCode.query.filter_by(
            code=code,
            application_id=oauth_app.id,
            used=True
        ).first()
        
        if used_code:
            return jsonify({
                'error': 'Authorization code already used',
                'error_code': 'CODE_ALREADY_USED',
                'message': 'This authorization code has already been exchanged for tokens',
                'how_to_fix': 'Authorization codes can only be used once. Start a new OAuth flow to get a fresh code'
            }), 400

        wrong_redirect = OAuthAuthorizationCode.query.filter_by(
            code=code,
            application_id=oauth_app.id,
            used=False
        ).first()
        
        if wrong_redirect and wrong_redirect.redirect_uri != redirect_uri:
            return jsonify({
                'error': 'Redirect URI mismatch',
                'error_code': 'REDIRECT_URI_MISMATCH',
                'message': 'The redirect_uri does not match the one used during authorization',
                'expected': wrong_redirect.redirect_uri,
                'received': redirect_uri,
                'how_to_fix': 'Use the same redirect_uri that was used in the authorization request'
            }), 400

        return jsonify({
            'error': 'Invalid authorization code',
            'error_code': 'INVALID_AUTHORIZATION_CODE',
            'message': 'The provided authorization code is invalid or does not exist',
            'how_to_fix': 'Verify the authorization code is correct and has not expired'
        }), 400

    # Check if code is expired
    if auth_code.expires_at < datetime.now(timezone.utc):
        return jsonify({
            'error': 'Authorization code expired',
            'error_code': 'CODE_EXPIRED',
            'message': f'Authorization code expired at {auth_code.expires_at.isoformat()}',
            'expires_at': auth_code.expires_at.isoformat(),
            'how_to_fix': 'Authorization codes expire after 10 minutes. Start a new OAuth flow to get a fresh code'
        }), 400

    # Mark code as used
    auth_code.used = True

    # Generate access token
    oauth_token = OAuthToken(
        user_id=auth_code.user_id,
        application_id=oauth_app.id
    )
    oauth_token.generate_tokens()
    oauth_token.set_scopes(auth_code.get_scopes())

    db.session.add(oauth_token)
    db.session.commit()

    return jsonify({
        'access_token': oauth_token.access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': oauth_token.refresh_token,
        'scope': ' '.join(oauth_token.get_scopes())
    })

@app.route('/oauth/user', methods=['GET'])
@oauth_required()
@limiter.limit("200 per hour")
def oauth_user():
    user = request.oauth_user

    # Get current identity verification status and address information
    identity_status = 'unverified'
    rejection_reason = None
    address_info = None
    
    if user.identity_token:
        identity_info = hackclub_identity_service.get_user_identity(user.identity_token)
        if identity_info and 'identity' in identity_info:
            identity_status = identity_info['identity'].get('verification_status', 'unverified')
            rejection_reason = identity_info['identity'].get('rejection_reason')
            
            # Extract address information from various possible locations in response
            address_info = None
            
            # Check for address in different locations in the response
            if 'address' in identity_info:
                address_info = {
                    'street_address': identity_info['address'].get('street_address'),
                    'locality': identity_info['address'].get('locality'),
                    'region': identity_info['address'].get('region'),
                    'postal_code': identity_info['address'].get('postal_code'),
                    'country': identity_info['address'].get('country')
                }
            elif 'identity' in identity_info and 'address' in identity_info['identity']:
                # Sometimes address is nested under identity
                addr = identity_info['identity']['address']
                address_info = {
                    'street_address': addr.get('street_address') or addr.get('line1'),
                    'locality': addr.get('locality') or addr.get('city'),
                    'region': addr.get('region') or addr.get('state'),
                    'postal_code': addr.get('postal_code') or addr.get('zip'),
                    'country': addr.get('country')
                }
            elif 'user' in identity_info and 'address' in identity_info['user']:
                # Check under user object
                addr = identity_info['user']['address']
                address_info = {
                    'street_address': addr.get('street_address') or addr.get('line1'),
                    'locality': addr.get('locality') or addr.get('city'),
                    'region': addr.get('region') or addr.get('state'),
                    'postal_code': addr.get('postal_code') or addr.get('zip'),
                    'country': addr.get('country')
                }
            
            # Filter out None/empty values
            if address_info:
                address_info = {k: v for k, v in address_info.items() if v}
                if not address_info:  # If all values were None/empty
                    address_info = None
            
            app.logger.debug(f"Extracted address info: {address_info}")
            
            # Update database if status changed
            verified = (identity_status == 'verified')
            if user.identity_verified != verified:
                user.identity_verified = verified
                db.session.commit()

    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'identity_verified': user.identity_verified,
        'identity_verification_status': identity_status,
        'identity_rejection_reason': rejection_reason,
        'address': address_info
    }

    return jsonify({'user': user_data})

@app.route('/oauth/user/clubs', methods=['GET'])
@oauth_required(['clubs:read'])
@limiter.limit("200 per hour")
def oauth_user_clubs():
    user = request.oauth_user
    
    # Get clubs where user is leader
    led_clubs = Club.query.filter_by(leader_id=user.id).all()
    
    # Get clubs where user is member
    memberships = ClubMembership.query.filter_by(user_id=user.id).all()
    member_clubs = [m.club for m in memberships]
    
    clubs_data = []
    
    # Add led clubs
    for club in led_clubs:
        airtable_data = club.get_airtable_data()
        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'location': club.location,
            'role': 'leader',
            'member_count': len(club.members) + 1,
            'balance': float(club.balance),
            'join_code': club.join_code,
            'created_at': club.created_at.isoformat() if club.created_at else None,
            'airtable_data': airtable_data
        })
    
    # Add member clubs
    for club in member_clubs:
        airtable_data = club.get_airtable_data()
        membership = next(m for m in memberships if m.club_id == club.id)
        clubs_data.append({
            'id': club.id,
            'name': club.name,
            'description': club.description,
            'location': club.location,
            'role': membership.role,
            'member_count': len(club.members) + 1,
            'joined_at': membership.joined_at.isoformat() if membership.joined_at else None,
            'airtable_data': airtable_data
        })
    
    return jsonify({
        'clubs': clubs_data,
        'total_clubs': len(clubs_data),
        'clubs_led': len(led_clubs),
        'clubs_joined': len(member_clubs)
    })

@app.route('/oauth/user/projects', methods=['GET'])
@oauth_required(['projects:read'])
@limiter.limit("200 per hour")
def oauth_user_projects():
    user = request.oauth_user
    
    # Get all projects by this user
    projects = ClubProject.query.filter_by(user_id=user.id).order_by(ClubProject.updated_at.desc()).all()
    
    projects_data = []
    for project in projects:
        projects_data.append({
            'id': project.id,
            'name': project.name,
            'description': project.description,
            'url': project.url,
            'github_url': project.github_url,
            'featured': project.featured,
            'club': {
                'id': project.club.id,
                'name': project.club.name
            },
            'created_at': project.created_at.isoformat() if project.created_at else None,
            'updated_at': project.updated_at.isoformat() if project.updated_at else None
        })
    
    return jsonify({
        'projects': projects_data,
        'total_projects': len(projects_data)
    })

@app.route('/oauth/user/assignments', methods=['GET'])
@oauth_required(['assignments:read'])
@limiter.limit("200 per hour")
def oauth_user_assignments():
    user = request.oauth_user
    
    # Get clubs where user is member or leader
    led_club_ids = [club.id for club in Club.query.filter_by(leader_id=user.id).all()]
    member_club_ids = [m.club_id for m in ClubMembership.query.filter_by(user_id=user.id).all()]
    all_club_ids = list(set(led_club_ids + member_club_ids))
    
    # Get assignments from all user's clubs
    assignments = ClubAssignment.query.filter(ClubAssignment.club_id.in_(all_club_ids)).order_by(ClubAssignment.created_at.desc()).all()
    
    assignments_data = []
    for assignment in assignments:
        assignments_data.append({
            'id': assignment.id,
            'title': assignment.title,
            'description': assignment.description,
            'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
            'status': assignment.status,
            'club': {
                'id': assignment.club.id,
                'name': assignment.club.name
            },
            'created_at': assignment.created_at.isoformat() if assignment.created_at else None
        })
    
    return jsonify({
        'assignments': assignments_data,
        'total_assignments': len(assignments_data)
    })

@app.route('/oauth/user/meetings', methods=['GET'])
@oauth_required(['meetings:read'])
@limiter.limit("200 per hour")
def oauth_user_meetings():
    user = request.oauth_user
    
    # Get clubs where user is member or leader
    led_club_ids = [club.id for club in Club.query.filter_by(leader_id=user.id).all()]
    member_club_ids = [m.club_id for m in ClubMembership.query.filter_by(user_id=user.id).all()]
    all_club_ids = list(set(led_club_ids + member_club_ids))
    
    # Get meetings from all user's clubs
    meetings = ClubMeeting.query.filter(ClubMeeting.club_id.in_(all_club_ids)).order_by(ClubMeeting.meeting_date.desc()).all()
    
    meetings_data = []
    for meeting in meetings:
        meetings_data.append({
            'id': meeting.id,
            'title': meeting.title,
            'description': meeting.description,
            'meeting_date': meeting.meeting_date.isoformat(),
            'start_time': meeting.start_time,
            'end_time': meeting.end_time,
            'location': meeting.location,
            'meeting_link': meeting.meeting_link,
            'club': {
                'id': meeting.club.id,
                'name': meeting.club.name
            },
            'created_at': meeting.created_at.isoformat() if meeting.created_at else None
        })
    
    return jsonify({
        'meetings': meetings_data,
        'total_meetings': len(meetings_data)
    })


@app.route('/oauth/debug')
def oauth_debug():
    return render_template('oauth_debug.html')

@app.route('/oauth/debug/callback')
def oauth_debug_callback():
    # This is just a callback endpoint for the debug page
    # It will show the authorization code in the URL for testing
    return render_template('oauth_debug.html')

@app.route('/api/docs')
def api_documentation():
    return render_template('api_docs.html')

# Template context processors and filters for cosmetics
@app.context_processor
def inject_cosmetic_functions():
    def get_member_cosmetics(club_id, user_id):
        """Get cosmetic effects for a member in a specific club"""
        try:
            # Get member cosmetics assigned to this user in this club
            member_cosmetics = MemberCosmetic.query.filter_by(
                club_id=club_id,
                user_id=user_id
            ).all()
            
            # Get club cosmetics that are available
            club_cosmetics = ClubCosmetic.query.filter_by(club_id=club_id).all()
            
            # Combine effects
            effects = []
            for cosmetic in member_cosmetics:
                if cosmetic.club_cosmetic:
                    effects.append({
                        'type': cosmetic.club_cosmetic.cosmetic_type,
                        'name': cosmetic.club_cosmetic.cosmetic_name
                    })
            
            return effects
        except Exception:
            return []
    
    def get_cosmetic_css_class(effects):
        """Convert cosmetic effects to CSS classes"""
        css_classes = []
        for effect in effects:
            effect_type = effect.get('type', '').lower()
            effect_name = effect.get('name', '').lower()
            
            if effect_type == 'text_effect':
                if 'rainbow' in effect_name:
                    css_classes.append('cosmetic-rainbow')
                elif 'gold' in effect_name:
                    css_classes.append('cosmetic-gold')
                elif 'fire' in effect_name:
                    css_classes.append('cosmetic-fire')
                elif 'ice' in effect_name:
                    css_classes.append('cosmetic-ice')
                elif 'neon' in effect_name:
                    css_classes.append('cosmetic-neon')
                elif 'gradient' in effect_name:
                    css_classes.append('cosmetic-gradient')
                elif 'sparkle' in effect_name:
                    css_classes.append('cosmetic-sparkle')
                elif 'shadow' in effect_name:
                    css_classes.append('cosmetic-shadow')
        
        return ' '.join(css_classes)
    
    def apply_member_cosmetics(club_id, user_id, username):
        """Apply cosmetic effects to a member's username"""
        user = User.query.get(user_id)
        # Properly escape the username to prevent XSS
        escaped_username = html.escape(username) if username else ''
        result = escaped_username

        # Check if user is admin and add lightning bolt
        if user and user.is_admin:
            result = f'{escaped_username} <i class="fas fa-bolt" style="color: #fbbf24; margin-left: 4px;" title="Admin"></i>'

        # Apply existing cosmetic effects
        effects = get_member_cosmetics(club_id, user_id)
        if effects:
            css_class = get_cosmetic_css_class(effects)
            if css_class:
                # Also sanitize the CSS class to prevent class injection
                safe_css_class = sanitize_html_attribute(css_class)
                result = f'<span class="{safe_css_class}">{result}</span>'

        return result
    
    return dict(
        get_member_cosmetics=get_member_cosmetics,
        get_cosmetic_css_class=get_cosmetic_css_class,
        apply_member_cosmetics=apply_member_cosmetics
    )

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(429)
def rate_limit_error(error):
    return render_template('429.html'), 429

if __name__ == '__main__':

    # Configure logging for production
    if os.getenv('FLASK_ENV') == 'production':
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(name)s %(message)s',
            handlers=[logging.StreamHandler()]
        )
        app.logger.setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
        app.logger.setLevel(logging.DEBUG)

@api_route('/api/club/<int:club_id>/quests', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def get_club_quests(club_id):
    current_user = get_current_user()
    club = Club.query.get_or_404(club_id)
    
    # Check if user has access to this club
    is_leader = club.leader_id == current_user.id
    is_co_leader = is_user_co_leader(club, current_user)
    is_member = ClubMembership.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    
    if not is_leader and not is_co_leader and not is_member and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        week_start = get_current_week_start()
        quests = WeeklyQuest.query.filter_by(is_active=True).all()
        
        quest_data = []
        for quest in quests:
            # Get progress for this week
            progress = ClubQuestProgress.query.filter_by(
                club_id=club_id,
                quest_id=quest.id,
                week_start=week_start
            ).first()
            
            target = 1 if quest.quest_type == 'gallery_post' else 5
            current_progress = progress.progress if progress else 0
            completed = progress.completed if progress else False
            
            quest_data.append({
                'id': quest.id,
                'name': quest.name,
                'description': quest.description,
                'quest_type': quest.quest_type,
                'reward_tokens': quest.reward_tokens,
                'target': target,
                'progress': current_progress,
                'completed': completed,
                'percentage': min(100, (current_progress / target) * 100)
            })
        
        # Calculate time until next Monday
        today = datetime.now()
        days_until_monday = (7 - today.weekday()) % 7
        if days_until_monday == 0:  # If today is Monday
            days_until_monday = 7
        next_monday = today + timedelta(days=days_until_monday)
        next_monday = next_monday.replace(hour=0, minute=0, second=0, microsecond=0)
        time_remaining = next_monday - today
        
        return jsonify({
            'quests': quest_data,
            'week_start': week_start.isoformat(),
            'time_remaining': {
                'days': time_remaining.days,
                'hours': time_remaining.seconds // 3600,
                'minutes': (time_remaining.seconds % 3600) // 60
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching quest data: {str(e)}")
        return jsonify({'error': 'Failed to fetch quest data'}), 500

@api_route('/admin/api/settings', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def get_settings():
    """Get all system settings"""
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        app.logger.info("get_settings: Starting to fetch system settings")
        
        # Get all settings
        settings = {}
        app.logger.debug("get_settings: Fetching maintenance_mode setting")
        maintenance_mode = SystemSettings.get_setting('maintenance_mode', 'false')
        app.logger.debug("get_settings: Fetching economy_enabled setting")
        economy_enabled = SystemSettings.get_setting('economy_enabled', 'true')
        app.logger.debug("get_settings: Fetching admin_economy_override setting")
        admin_economy_override = SystemSettings.get_setting('admin_economy_override', 'false')
        app.logger.debug("get_settings: Fetching club_creation_enabled setting")
        club_creation_enabled = SystemSettings.get_setting('club_creation_enabled', 'true')
        app.logger.debug("get_settings: Fetching user_registration_enabled setting")
        user_registration_enabled = SystemSettings.get_setting('user_registration_enabled', 'true')
        app.logger.debug("get_settings: Fetching mobile_enabled setting")
        mobile_enabled = SystemSettings.get_setting('mobile_enabled', 'true')
        app.logger.debug("get_settings: Fetching heidi_enabled setting")
        heidi_enabled = SystemSettings.get_setting('heidi_enabled', 'true')
        app.logger.debug("get_settings: Fetching banner_enabled setting")
        banner_enabled = SystemSettings.get_setting('banner_enabled', 'false')
        
        settings['maintenance_mode'] = maintenance_mode
        settings['economy_enabled'] = economy_enabled
        settings['admin_economy_override'] = admin_economy_override
        settings['club_creation_enabled'] = club_creation_enabled
        settings['user_registration_enabled'] = user_registration_enabled
        settings['mobile_enabled'] = mobile_enabled
        settings['heidi_enabled'] = heidi_enabled
        settings['banner_enabled'] = banner_enabled
        
        return jsonify({
            'success': True,
            'settings': settings
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching settings: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch settings'}), 500

@api_route('/admin/api/settings', methods=['POST'])
@admin_required
@limiter.limit("50 per hour")
def update_setting():
    """Update a system setting"""
    current_user = get_current_user()
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        key = data.get('key')
        value = data.get('value')
        
        if not key or value is None:
            return jsonify({'success': False, 'message': 'Key and value are required'}), 400
        
        # Validate settings keys
        valid_keys = ['maintenance_mode', 'economy_enabled', 'admin_economy_override', 'club_creation_enabled', 'user_registration_enabled', 'mobile_enabled', 'heidi_enabled', 'banner_enabled']
        if key not in valid_keys:
            return jsonify({'success': False, 'message': f'Invalid setting key: {key}'}), 400
        
        # Validate values
        if value not in ['true', 'false']:
            return jsonify({'success': False, 'message': 'Setting value must be "true" or "false"'}), 400
        
        # Update the setting
        SystemSettings.set_setting(key, value, current_user.id)
        
        app.logger.info(f"Setting {key} updated to {value} by admin {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': f'Setting {key} updated successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error updating setting: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to update setting'}), 500

@api_route('/admin/api/banner-settings', methods=['GET'])
@admin_required
@limiter.limit("100 per hour")
def get_banner_settings():
    """Get banner settings"""
    try:
        # Get banner settings from system settings
        settings = {
            'enabled': SystemSettings.get_setting('banner_enabled', 'false'),
            'title': SystemSettings.get_setting('banner_title', 'Design Contest'),
            'subtitle': SystemSettings.get_setting('banner_subtitle', 'Submit your creative projects and win amazing prizes!'),
            'icon': SystemSettings.get_setting('banner_icon', 'fas fa-palette'),
            'primary_color': SystemSettings.get_setting('banner_primary_color', '#ec3750'),
            'secondary_color': SystemSettings.get_setting('banner_secondary_color', '#d63146'),
            'background_color': SystemSettings.get_setting('banner_background_color', '#ffffff'),
            'text_color': SystemSettings.get_setting('banner_text_color', '#1a202c'),
            'link_url': SystemSettings.get_setting('banner_link_url', '/gallery'),
            'link_text': SystemSettings.get_setting('banner_link_text', 'Submit Entry')
        }
        
        return jsonify({
            'success': True,
            'settings': settings
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching banner settings: {str(e)}")
        return jsonify({'success': False, 'message': 'Failed to fetch banner settings'}), 500

@api_route('/admin/api/banner-settings', methods=['POST'])
@admin_required
@limiter.limit("50 per hour")
def update_banner_settings():
    """Update banner settings"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Update all banner settings
        settings_map = {
            'enabled': 'banner_enabled',
            'title': 'banner_title',
            'subtitle': 'banner_subtitle',
            'icon': 'banner_icon',
            'primary_color': 'banner_primary_color',
            'secondary_color': 'banner_secondary_color',
            'background_color': 'banner_background_color',
            'text_color': 'banner_text_color',
            'link_url': 'banner_link_url',
            'link_text': 'banner_link_text'
        }
        
        for field, setting_key in settings_map.items():
            if field in data:
                if field == 'enabled':
                    value = 'true' if data[field] else 'false'
                elif field in ['primary_color', 'secondary_color', 'background_color', 'text_color']:
                    # Sanitize color values specifically
                    value = sanitize_css_color(data[field])
                elif field == 'icon':
                    # Sanitize CSS class names for icons
                    value = sanitize_html_attribute(data[field], max_length=100)
                elif field == 'link_url':
                    # Sanitize URLs
                    value = sanitize_url(data[field], max_length=500)
                elif field in ['title', 'subtitle', 'link_text']:
                    # Sanitize text content
                    value = sanitize_string(data[field], max_length=200)
                else:
                    # Default sanitization
                    value = sanitize_string(data[field], max_length=500)

                SystemSettings.set_setting(setting_key, value, current_user.id)
        
        app.logger.info(f"Banner settings updated by admin {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': 'Banner settings updated successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error updating banner settings: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to update banner settings'}), 500

# Status Page Routes
@app.route('/status')
def status_page():
    """Public status page - no login required"""
    return render_template('status.html')

# Status API Endpoints
@api_route('/api/status/incidents', methods=['GET'])
def get_status_incidents():
    """Get all incidents (public endpoint)"""
    try:
        # Get query parameters
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        status_filter = request.args.get('status')  # resolved, active, etc.
        
        query = StatusIncident.query.order_by(StatusIncident.created_at.desc())
        
        # Apply status filter
        if status_filter:
            if status_filter == 'active':
                query = query.filter(StatusIncident.status.in_(['investigating', 'identified', 'monitoring']))
            elif status_filter == 'resolved':
                query = query.filter(StatusIncident.status == 'resolved')
            else:
                query = query.filter(StatusIncident.status == status_filter)
        
        # Apply pagination
        incidents = query.offset(offset).limit(limit).all()
        total = query.count()
        
        return jsonify({
            'incidents': [incident.to_dict() for incident in incidents],
            'total': total,
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching status incidents: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/status/incidents/<int:incident_id>', methods=['GET'])
def get_status_incident(incident_id):
    """Get specific incident with updates (public endpoint)"""
    try:
        incident = StatusIncident.query.get_or_404(incident_id)
        incident_data = incident.to_dict()
        incident_data['updates'] = [update.to_dict() for update in incident.updates]
        
        return jsonify(incident_data)
        
    except Exception as e:
        app.logger.error(f"Error fetching status incident {incident_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/status/summary', methods=['GET'])
def get_status_summary():
    """Get overall system status summary (public endpoint)"""
    try:
        # Count active incidents by impact level
        active_incidents = StatusIncident.query.filter(
            StatusIncident.status.in_(['investigating', 'identified', 'monitoring'])
        ).all()
        
        # Determine overall status
        if not active_incidents:
            overall_status = 'operational'
            status_message = 'All systems operational'
        elif any(incident.impact == 'critical' for incident in active_incidents):
            overall_status = 'major_outage'
            status_message = 'Major service disruption'
        elif any(incident.impact == 'major' for incident in active_incidents):
            overall_status = 'partial_outage'
            status_message = 'Some systems affected'
        else:
            overall_status = 'degraded'
            status_message = 'Minor service issues'
        
        # Get service status
        services = [
            {'name': 'Dashboard', 'status': 'operational'},
            {'name': 'API', 'status': 'operational'},
            {'name': 'Authentication', 'status': 'operational'},
            {'name': 'CDN', 'status': 'operational'},
            {'name': 'Database', 'status': 'operational'},
            {'name': 'Economy', 'status': 'operational'}
        ]
        
        # Update service status based on active incidents
        for incident in active_incidents:
            affected = incident.get_affected_services()
            for service_name in affected:
                for service in services:
                    if service['name'].lower() == service_name.lower():
                        if incident.impact == 'critical':
                            service['status'] = 'major_outage'
                        elif incident.impact == 'major':
                            service['status'] = 'partial_outage'
                        else:
                            service['status'] = 'degraded'
        
        return jsonify({
            'overall_status': overall_status,
            'status_message': status_message,
            'services': services,
            'active_incidents_count': len(active_incidents),
            'last_updated': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Error getting status summary: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/status/banner', methods=['GET'])
def get_status_banner():
    """Get incident banner data for site-wide display (lightweight endpoint)"""
    try:
        # Get active incidents with high impact priority
        active_incidents = StatusIncident.query.filter(
            StatusIncident.status.in_(['investigating', 'identified', 'monitoring'])
        ).order_by(
            # Order by impact priority: critical > major > minor
            db.case(
                (StatusIncident.impact == 'critical', 1),
                (StatusIncident.impact == 'major', 2),
                (StatusIncident.impact == 'minor', 3),
                else_=4
            ),
            StatusIncident.created_at.desc()
        ).limit(3).all()  # Only get top 3 most severe incidents
        
        if not active_incidents:
            return jsonify({
                'has_active_incidents': False,
                'incidents': [],
                'banner_severity': 'none'
            })
        
        # Determine banner severity based on highest impact incident
        highest_impact = active_incidents[0].impact
        banner_severity = 'critical' if highest_impact == 'critical' else \
                         'major' if highest_impact == 'major' else 'minor'
        
        # Format incidents for banner display
        banner_incidents = []
        for incident in active_incidents:
            banner_incidents.append({
                'id': incident.id,
                'title': incident.title,
                'impact': incident.impact,
                'status': incident.status,
                'duration': incident.get_duration(),
                'affected_services': incident.get_affected_services()
            })
        
        return jsonify({
            'has_active_incidents': True,
            'incidents': banner_incidents,
            'banner_severity': banner_severity,
            'total_count': len(active_incidents),
            'last_updated': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Error getting status banner: {str(e)}")
        return jsonify({
            'has_active_incidents': False,
            'incidents': [],
            'banner_severity': 'none'
        })

# Admin Status Management Endpoints
@api_route('/api/admin/status/incidents', methods=['POST'])
@admin_required
def create_status_incident():
    """Create new status incident (admin only)"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'description', 'impact']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Create incident
        incident = StatusIncident(
            title=sanitize_string(data['title'], 255),
            description=sanitize_string(data['description'], allow_html=False),
            impact=data['impact'],
            status=data.get('status', 'investigating'),
            created_by=get_current_user().id
        )
        
        # Set affected services
        if data.get('affected_services'):
            incident.set_affected_services(data['affected_services'])
        
        db.session.add(incident)
        db.session.commit()
        
        # Log the action
        create_audit_log(
            action_type='status_incident_created',
            description=f"Admin {get_current_user().username} created status incident: {incident.title}",
            user=get_current_user(),
            target_type='status_incident',
            target_id=incident.id,
            details={'title': incident.title, 'impact': incident.impact},
            admin_action=True,
            category='admin'
        )
        
        return jsonify(incident.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating status incident: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/admin/status/incidents/<int:incident_id>', methods=['PUT'])
@admin_required
def update_status_incident(incident_id):
    """Update status incident (admin only)"""
    try:
        incident = StatusIncident.query.get_or_404(incident_id)
        data = request.get_json()
        
        # Update fields
        if 'title' in data:
            incident.title = sanitize_string(data['title'], 255)
        if 'description' in data:
            incident.description = sanitize_string(data['description'], allow_html=False)
        if 'status' in data:
            old_status = incident.status
            incident.status = data['status']
            # Auto-set resolved_at when status changes to resolved
            if data['status'] == 'resolved' and old_status != 'resolved':
                incident.resolved_at = datetime.now(timezone.utc)
            elif data['status'] != 'resolved':
                incident.resolved_at = None
        if 'impact' in data:
            incident.impact = data['impact']
        if 'affected_services' in data:
            incident.set_affected_services(data['affected_services'])
        
        db.session.commit()
        
        # Log the action
        create_audit_log(
            action_type='status_incident_updated',
            description=f"Admin {get_current_user().username} updated status incident: {incident.title}",
            user=get_current_user(),
            target_type='status_incident',
            target_id=incident.id,
            details={'changes': data},
            admin_action=True,
            category='admin'
        )
        
        return jsonify(incident.to_dict())
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating status incident {incident_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/admin/status/incidents/<int:incident_id>/updates', methods=['POST'])
@admin_required
def add_status_update(incident_id):
    """Add status update to incident (admin only)"""
    try:
        incident = StatusIncident.query.get_or_404(incident_id)
        data = request.get_json()
        
        if not data.get('message'):
            return jsonify({'error': 'Message is required'}), 400
        
        # Create status update
        update = StatusUpdate(
            incident_id=incident_id,
            message=sanitize_string(data['message'], allow_html=False),
            status=data.get('status', incident.status),
            created_by=get_current_user().id
        )
        
        # Update incident status if provided
        if 'status' in data and data['status'] != incident.status:
            old_status = incident.status
            incident.status = data['status']
            # Auto-set resolved_at when status changes to resolved
            if data['status'] == 'resolved' and old_status != 'resolved':
                incident.resolved_at = datetime.now(timezone.utc)
            elif data['status'] != 'resolved':
                incident.resolved_at = None
        
        db.session.add(update)
        db.session.commit()
        
        # Log the action
        create_audit_log(
            action_type='status_update_added',
            description=f"Admin {get_current_user().username} added update to incident: {incident.title}",
            user=get_current_user(),
            target_type='status_incident',
            target_id=incident_id,
            details={'message': update.message, 'status': update.status},
            admin_action=True,
            category='admin'
        )
        
        return jsonify(update.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding status update to incident {incident_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_route('/api/admin/status/incidents/<int:incident_id>', methods=['DELETE'])
@admin_required
def delete_status_incident(incident_id):
    """Delete status incident (admin only)"""
    try:
        incident = StatusIncident.query.get_or_404(incident_id)
        
        # Store info for logging
        incident_title = incident.title
        
        # Delete associated updates first
        StatusUpdate.query.filter_by(incident_id=incident_id).delete()
        
        # Delete incident
        db.session.delete(incident)
        db.session.commit()
        
        # Log the action
        create_audit_log(
            action_type='status_incident_deleted',
            description=f"Admin {get_current_user().username} deleted status incident: {incident_title}",
            user=get_current_user(),
            target_type='status_incident',
            target_id=incident_id,
            details={'title': incident_title},
            admin_action=True,
            category='admin'
        )
        
        return jsonify({'message': 'Incident deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting status incident {incident_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Admin API endpoints for mobile
@app.route('/api/admin/stats')
@admin_required
def admin_stats_api():
    total_users = User.query.count()
    total_clubs = Club.query.count()
    total_posts = ClubPost.query.count()
    total_assignments = ClubAssignment.query.count()
    total_club_balance = db.session.query(db.func.sum(Club.balance)).scalar() or 0
    
    return jsonify({
        'total_users': total_users,
        'total_clubs': total_clubs,
        'total_posts': total_posts,
        'total_assignments': total_assignments,
        'total_club_balance': float(total_club_balance)
    })

@app.route('/api/admin/users')
@admin_required
def admin_users_api():
    search = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = 20
    
    query = User.query
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'users': [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'created_at': user.created_at.isoformat() if user.created_at else None
        } for user in users.items],
        'has_next': users.has_next,
        'page': page
    })

@app.route('/api/admin/clubs')
@admin_required
def admin_clubs_api():
    search = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = 20
    
    query = Club.query
    if search:
        query = query.filter(Club.name.ilike(f'%{search}%'))
    
    clubs = query.order_by(Club.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'clubs': [{
            'id': club.id,
            'name': club.name,
            'balance': float(club.balance),
            'member_count': ClubMembership.query.filter_by(club_id=club.id).count(),
            'created_at': club.created_at.isoformat() if club.created_at else None
        } for club in clubs.items],
        'has_next': clubs.has_next,
        'page': page
    })

@app.route('/api/admin/activity')
@admin_required
def admin_activity_api():
    page = int(request.args.get('page', 1))
    per_page = 20
    
    posts = ClubPost.query.order_by(ClubPost.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'activities': [{
            'id': post.id,
            'title': post.title,
            'club_name': post.club.name if post.club else 'Unknown',
            'author_username': post.author.username if post.author else 'Unknown',
            'created_at': post.created_at.isoformat() if post.created_at else None
        } for post in posts.items],
        'has_next': posts.has_next,
        'page': page
    })

@app.route('/api/admin/settings', methods=['POST'])
@admin_required
def admin_settings_api():
    data = request.get_json()
    setting = data.get('setting')
    value = data.get('value')
    
    if not setting:
        return jsonify({'error': 'Setting is required'}), 400
    
    valid_settings = ['maintenance_mode', 'economy_enabled', 'club_creation_enabled', 
                     'user_registration_enabled', 'mobile_enabled', 'heidi_enabled']
    
    if setting not in valid_settings:
        return jsonify({'error': 'Invalid setting'}), 400
    
    # Convert boolean strings to actual booleans
    if isinstance(value, str):
        value = value.lower() == 'true'
    
    SystemSettings.set_setting(setting, str(value).lower())

    return jsonify({'message': f'{setting} updated to {value}'})

# ========== RBAC Management API Endpoints ==========

@app.route('/api/admin/rbac/roles')
@permission_required('system.manage_roles', 'admin.access_dashboard')
def get_all_roles():
    """Get all roles in the system"""
    roles = Role.query.all()
    return jsonify({
        'roles': [role.to_dict() for role in roles]
    })

@app.route('/api/admin/rbac/permissions')
@permission_required('system.manage_permissions', 'admin.access_dashboard')
def get_all_permissions():
    """Get all permissions in the system"""
    permissions = Permission.query.all()

    # Group by category
    grouped = {}
    for perm in permissions:
        if perm.category not in grouped:
            grouped[perm.category] = []
        grouped[perm.category].append(perm.to_dict())

    return jsonify({
        'permissions': grouped,
        'all_permissions': [p.to_dict() for p in permissions]
    })

@app.route('/api/admin/rbac/users/<int:user_id>/roles')
@permission_required('users.assign_roles', 'system.manage_roles')
def get_user_roles(user_id):
    """Get roles assigned to a specific user"""
    user = User.query.get_or_404(user_id)

    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'is_root': user.is_root_user(),
        'roles': [role.to_dict() for role in user.roles],
        'permissions': user.get_all_permissions()
    })

@app.route('/api/admin/rbac/users/<int:user_id>/roles', methods=['POST'])
@permission_required('users.assign_roles')
@limiter.limit("20 per hour")
def assign_role_to_user(user_id):
    """Assign a role to a user"""
    current_user = get_current_user()
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    role_name = data.get('role_name')
    if not role_name:
        return jsonify({'error': 'role_name is required'}), 400

    role = Role.query.filter_by(name=role_name).first()
    if not role:
        return jsonify({'error': 'Role not found'}), 404

    # Check if trying to assign super-admin role
    if role_name == 'super-admin' and not current_user.has_role('super-admin'):
        return jsonify({'error': 'Only super-admins can assign super-admin role'}), 403

    # Assign the role
    if user.assign_role(role, current_user):
        db.session.commit()

        # Create audit log
        create_audit_log(
            'role_assigned',
            f'{current_user.username} assigned role {role.display_name} to {user.username}',
            user=current_user,
            target_type='user',
            target_id=user.id,
            details={'role_name': role_name, 'target_username': user.username},
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'message': f'Role {role.display_name} assigned to {user.username}',
            'user_roles': [r.to_dict() for r in user.roles]
        })
    else:
        return jsonify({'error': 'User already has this role'}), 400

@app.route('/api/admin/rbac/users/<int:user_id>/roles/<role_name>', methods=['DELETE'])
@permission_required('users.assign_roles')
@limiter.limit("20 per hour")
def remove_role_from_user(user_id, role_name):
    """Remove a role from a user"""
    current_user = get_current_user()
    user = User.query.get_or_404(user_id)

    # Prevent removing root user's super-admin role
    if user.is_root_user() and role_name == 'super-admin':
        return jsonify({'error': 'Cannot remove super-admin role from root user'}), 403

    # Check if trying to remove super-admin role
    if role_name == 'super-admin' and not current_user.has_role('super-admin'):
        return jsonify({'error': 'Only super-admins can remove super-admin role'}), 403

    # Remove the role
    if user.remove_role(role_name):
        db.session.commit()

        # Create audit log
        create_audit_log(
            'role_removed',
            f'{current_user.username} removed role {role_name} from {user.username}',
            user=current_user,
            target_type='user',
            target_id=user.id,
            details={'role_name': role_name, 'target_username': user.username},
            admin_action=True,
            category='admin'
        )

        return jsonify({
            'message': f'Role {role_name} removed from {user.username}',
            'user_roles': [r.to_dict() for r in user.roles]
        })
    else:
        return jsonify({'error': 'User does not have this role or role not found'}), 400

@app.route('/api/admin/rbac/roles', methods=['POST'])
@permission_required('system.manage_roles')
@limiter.limit("10 per hour")
def create_role():
    """Create a new custom role"""
    current_user = get_current_user()
    data = request.get_json()

    name = data.get('name')
    display_name = data.get('display_name')
    description = data.get('description', '')
    permission_names = data.get('permissions', [])

    if not name or not display_name:
        return jsonify({'error': 'name and display_name are required'}), 400

    # Check if role already exists
    if Role.query.filter_by(name=name).first():
        return jsonify({'error': 'Role already exists'}), 400

    # Create the role
    role = Role(
        name=name,
        display_name=display_name,
        description=description,
        is_system_role=False
    )
    db.session.add(role)
    db.session.flush()

    # Assign permissions
    for perm_name in permission_names:
        perm = Permission.query.filter_by(name=perm_name).first()
        if perm:
            role_perm = RolePermission(role_id=role.id, permission_id=perm.id)
            db.session.add(role_perm)

    db.session.commit()

    # Create audit log
    create_audit_log(
        'role_created',
        f'{current_user.username} created role {role.display_name}',
        user=current_user,
        target_type='role',
        target_id=role.id,
        details={'role_name': name, 'permissions': permission_names},
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'message': f'Role {display_name} created successfully',
        'role': role.to_dict()
    }), 201

@app.route('/api/admin/rbac/roles/<int:role_id>', methods=['PUT'])
@permission_required('system.manage_roles')
@limiter.limit("20 per hour")
def update_role(role_id):
    """Update a role's permissions"""
    current_user = get_current_user()
    role = Role.query.get_or_404(role_id)

    data = request.get_json()
    permission_names = data.get('permissions', [])

    # Validate input
    if not permission_names or len(permission_names) == 0:
        return jsonify({'error': 'At least one permission is required'}), 400

    # Remove all existing permissions
    RolePermission.query.filter_by(role_id=role.id).delete()

    # Add new permissions
    for perm_name in permission_names:
        perm = Permission.query.filter_by(name=perm_name).first()
        if perm:
            role_perm = RolePermission(role_id=role.id, permission_id=perm.id)
            db.session.add(role_perm)

    # Update other fields if provided
    if 'display_name' in data:
        role.display_name = data['display_name']
    if 'description' in data:
        role.description = data['description']

    db.session.commit()

    # Create audit log
    create_audit_log(
        'role_updated',
        f'{current_user.username} updated role {role.display_name}',
        user=current_user,
        target_type='role',
        target_id=role.id,
        details={'role_name': role.name, 'permissions': permission_names},
        admin_action=True,
        category='admin'
    )

    return jsonify({
        'message': f'Role {role.display_name} updated successfully',
        'role': role.to_dict()
    })

@app.route('/api/admin/rbac/roles/<int:role_id>', methods=['DELETE'])
@permission_required('system.manage_roles')
@limiter.limit("10 per hour")
def delete_role(role_id):
    """Delete a custom role"""
    current_user = get_current_user()
    role = Role.query.get_or_404(role_id)

    # Check if force parameter is provided
    force = request.args.get('force', 'false').lower() == 'true'

    # Check if role is assigned to any users
    user_roles = UserRole.query.filter_by(role_id=role.id).all()
    user_count = len(user_roles)

    if user_count > 0 and not force:
        # Return info about users with this role
        return jsonify({
            'error': f'This role is assigned to {user_count} user(s)',
            'user_count': user_count,
            'requires_confirmation': True
        }), 409  # Conflict status code

    role_name = role.display_name

    # If force is true, remove role from all users first
    if user_count > 0 and force:
        for user_role in user_roles:
            db.session.delete(user_role)

    # Delete role permissions
    RolePermission.query.filter_by(role_id=role.id).delete()

    # Delete role
    db.session.delete(role)
    db.session.commit()

    # Create audit log
    create_audit_log(
        'role_deleted',
        f'{current_user.username} deleted role {role_name}' + (f' (removed from {user_count} users)' if user_count > 0 else ''),
        user=current_user,
        details={'role_name': role.name, 'users_affected': user_count},
        admin_action=True,
        category='admin'
    )

    return jsonify({'message': f'Role {role_name} deleted successfully' + (f' and removed from {user_count} user(s)' if user_count > 0 else '')})

@app.route('/api/admin/rbac/initialize', methods=['POST'])
@permission_required('system.manage_roles')
def initialize_rbac():
    """Initialize or reinitialize the RBAC system"""
    current_user = get_current_user()

    try:
        initialize_rbac_system()

        # Create audit log
        create_audit_log(
            'rbac_initialized',
            f'{current_user.username} initialized the RBAC system',
            user=current_user,
            admin_action=True,
            category='admin',
            severity='warning'
        )

        return jsonify({'message': 'RBAC system initialized successfully'})
    except Exception as e:
        app.logger.error(f"RBAC initialization error: {str(e)}")
        return jsonify({'error': f'Failed to initialize RBAC: {str(e)}'}), 500

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()

    except Exception as e:
        app.logger.error(f"Database setup error: {e}")

    port = int(os.getenv('PORT', 5000))
    app.logger.info(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
