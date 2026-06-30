"""Security checks — each check inherits from SecurityCheck (base.py)."""

from mcp_bandit.checks.base import SecurityCheck

from mcp_bandit.checks.secrets import SecretsCheck
from mcp_bandit.checks.permissions import PermissionsCheck
from mcp_bandit.checks.poisoning import PoisoningCheck
from mcp_bandit.checks.supply_chain import SupplyChainCheck
from mcp_bandit.checks.injection import InjectionCheck
from mcp_bandit.checks.context_injection import ContextInjectionCheck
from mcp_bandit.checks.auth import AuthCheck
from mcp_bandit.checks.audit_gap import AuditGapCheck
from mcp_bandit.checks.shadow import ShadowCheck
from mcp_bandit.checks.context_sharing import ContextSharingCheck

ALL_CHECKS: list[SecurityCheck] = [
    SecretsCheck(),
    PermissionsCheck(),
    PoisoningCheck(),
    SupplyChainCheck(),
    InjectionCheck(),
    ContextInjectionCheck(),
    AuthCheck(),
    AuditGapCheck(),
    ShadowCheck(),
    ContextSharingCheck(),
]
