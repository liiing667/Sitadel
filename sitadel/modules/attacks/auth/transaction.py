"""Compatibility re-export of the JWT verification transaction.

The implementation lives in :mod:`jwttransaction`; this module keeps the
concept discoverable under the shorter name used by callers/tests.
"""

from .jwttransaction import *  # noqa: F401,F403

