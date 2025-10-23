"""
Business Logic Vulnerability Scanners
======================================

This package contains specialized scanners for detecting business logic flaws:
- Race Condition attacks
- Mass Assignment vulnerabilities
- Payment Logic flaws
- Workflow/Process Bypass issues

Author: ROBIN | @ll bUg
Part of: AlBaTTaR BUGS v1.0
"""

from .race_condition import RaceConditionScanner
from .mass_assignment import MassAssignmentScanner
from .payment_logic import PaymentLogicScanner
from .workflow_bypass import WorkflowBypassScanner

__all__ = [
    'RaceConditionScanner',
    'MassAssignmentScanner',
    'PaymentLogicScanner',
    'WorkflowBypassScanner'
]

__version__ = '1.0.0'
__author__ = 'ROBIN'
