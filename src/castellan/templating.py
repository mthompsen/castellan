"""Shared Jinja2 environment for markdown artifact templates."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from castellan.catalog import format_control_id


def jinja_env() -> Environment:
    """Environment with castellan's filters; autoescape off (markdown output)."""
    env = Environment(
        loader=PackageLoader("castellan", "templates"),
        autoescape=select_autoescape(default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["control_id"] = format_control_id
    env.filters["status_label"] = lambda value: str(value).replace("_", " ")
    return env
