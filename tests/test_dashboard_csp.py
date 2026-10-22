"""
The dashboard is served with `script-src 'self'`, which makes browsers refuse
inline event-handler attributes (onclick="..."). When that happened, every
dashboard button silently did nothing while the API tests all kept passing.
These tests keep the front-end compatible with the CSP.
"""

import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INLINE_HANDLER = re.compile(r"""\son[a-z]+\s*=\s*["']""", re.IGNORECASE)


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_dashboard_html_has_no_inline_event_handlers():
    assert not INLINE_HANDLER.search(_read("app/templates/index.html"))


def test_dashboard_js_does_not_generate_inline_event_handlers():
    assert not INLINE_HANDLER.search(_read("app/static/main.js"))


def test_dashboard_has_no_inline_script_blocks():
    html = _read("app/templates/index.html")
    inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html, re.IGNORECASE)
    assert inline_scripts == []


def test_every_data_action_has_a_handler():
    """wire-buttons.js calls window[name]; a data-action naming a function that
    main.js doesn't define would be a silently dead button."""
    html = _read("app/templates/index.html")
    js = _read("app/static/main.js")
    used = set(re.findall(r'data-action="(\w+)"', html + js))
    defined = set(re.findall(r"^(?:async\s+)?function\s+(\w+)", js, re.M))
    assert used, "expected data-action attributes in the dashboard"
    assert used <= defined, f"buttons with no handler: {used - defined}"


def test_dispatcher_is_loaded_by_the_page():
    assert 'src="/static/wire-buttons.js"' in _read("app/templates/index.html")
