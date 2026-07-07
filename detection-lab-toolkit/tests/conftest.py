"""Shared pytest configuration.

Adds the repo root to sys.path so the three top-level CLI modules
(lab_mgmt, lab_monitoring, lab_hardening) can be imported directly by
the test files, without needing to package them.
"""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
