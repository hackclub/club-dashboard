"""
Sanitization utilities for the Hack Club Dashboard.
Contains functions for sanitizing various types of user input to prevent XSS and injection attacks.
"""

import html
import re
import urllib.parse
import markdown
from markdown.extensions import codehilite
import bleach


def sanitize_string(value, max_length=None, allow_html=False):
    """Sanitize string input to prevent XSS and injection attacks"""
    if not value:
        return value

    value = str(value).strip()

    if max_length and len(value) > max_length:
        value = value[:max_length]

    if not allow_html:
        value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)
        value = re.sub(r'<(script|iframe|object|embed|form|input|button|link|style)[^>]*>', '', value, flags=re.IGNORECASE)
        value = html.escape(value)

    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value


def sanitize_css_value(value, max_length=None):
    """Sanitize CSS values to prevent CSS injection attacks"""
    if not value:
        return value

    value = str(value).strip()

    if max_length and len(value) > max_length:
        value = value[:max_length]

    value = re.sub(r'javascript:', '', value, flags=re.IGNORECASE)
    value = re.sub(r'data:(?!image/(png|jpeg|jpg|gif|webp|svg\+xml))', '', value, flags=re.IGNORECASE)
    value = re.sub(r'expression\s*\(', '', value, flags=re.IGNORECASE)
    value = re.sub(r'@import', '', value, flags=re.IGNORECASE)
    value = re.sub(r'url\s*\(\s*["\']?(?!https?:)[^)]*["\']?\s*\)', '', value, flags=re.IGNORECASE)
    value = re.sub(r'[;"{}]', '', value)
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value


def sanitize_css_color(value):
    """Sanitize CSS color values specifically"""
    if not value:
        return value

    value = str(value).strip()

    hex_pattern = r'^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$'
    rgb_pattern = r'^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*[01]?\.?\d*)?\s*\)$'
    hsl_pattern = r'^hsla?\(\s*(\d{1,3})\s*,\s*(\d{1,3})%\s*,\s*(\d{1,3})%\s*(?:,\s*[01]?\.?\d*)?\s*\)$'
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
        return '#000000'


def sanitize_html_attribute(value, max_length=None):
    """Sanitize values for HTML attributes to prevent attribute injection"""
    if not value:
        return value

    value = str(value).strip()

    if max_length and len(value) > max_length:
        value = value[:max_length]

    value = re.sub(r'["\'><=&]', '', value)
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    value = re.sub(r'\bon[a-z]+\s*=', '', value, flags=re.IGNORECASE)

    return value


def sanitize_url(value, max_length=None):
    """Sanitize URLs to prevent JavaScript injection and other attacks"""
    if not value:
        return value

    value = str(value).strip()

    if max_length and len(value) > max_length:
        value = value[:max_length]

    allowed_schemes = ['http', 'https', 'mailto', 'tel']

    try:
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme and parsed.scheme.lower() not in allowed_schemes:
            return '#'  # Return safe default

        if 'javascript:' in value.lower() or 'data:' in value.lower() or 'vbscript:' in value.lower():
            return '#'

        return value
    except:
        return '#'  # Return safe default if URL parsing fails


def markdown_to_html(markdown_content):
    """Convert markdown to safe HTML for club posts"""
    if not markdown_content:
        return ""

    md = markdown.Markdown(extensions=['extra', 'codehilite', 'nl2br'],
                          extension_configs={
                              'codehilite': {
                                  'css_class': 'highlight',
                                  'use_pygments': False
                              }
                          })

    html_content = md.convert(markdown_content)

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

    clean_html = bleach.clean(html_content,
                             tags=allowed_tags,
                             attributes=allowed_attributes,
                             protocols=['http', 'https', 'mailto'])

    return clean_html
