"""Vendored python-bidi 0.6.12 display reordering.

The Rust extension is not included. ``get_display`` is the pure-Python
algorithm, so the panel and the tests do not need another package.
"""

from .algorithm import get_display

__all__ = ["get_display"]
