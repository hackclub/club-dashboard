"""
Formatting utilities for the Hack Club Dashboard.
Contains functions for markdown conversion and template filters.
"""

import markdown
from markdown.extensions import codehilite
import bleach


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


def safe_css_color_filter(value):
    """Template filter for safe CSS color output"""
    from .sanitization import sanitize_css_color
    return sanitize_css_color(value)


def safe_css_value_filter(value):
    """Template filter for safe CSS value output"""
    from .sanitization import sanitize_css_value
    return sanitize_css_value(value)


def safe_html_attr_filter(value):
    """Template filter for safe HTML attribute output"""
    from .sanitization import sanitize_html_attribute
    return sanitize_html_attribute(value)


def safe_url_filter(value):
    """Template filter for safe URL output"""
    from .sanitization import sanitize_url
    return sanitize_url(value)
