"""Utility functions for FastMCP OAuth."""

from .crypto import generate_secret_key
from .urls import detect_base_url

__all__ = ["generate_secret_key", "detect_base_url"]