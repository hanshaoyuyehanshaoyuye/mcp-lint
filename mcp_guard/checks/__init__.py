"""Security checks — each check inherits from SecurityCheck (base.py)."""

from mcp_guard.checks.base import SecurityCheck, Severity, Finding, ScanTarget

from mcp_guard.checks.secrets import SecretsCheck
from mcp_guard.checks.injection import InjectionCheck
from mcp_guard.checks.permissions import PermissionsCheck
from mcp_guard.checks.poisoning import PoisoningCheck
from mcp_guard.checks.supply_chain import SupplyChainCheck
from mcp_guard.checks.auth import AuthCheck
from mcp_guard.checks.shadow import ShadowCheck

ALL_CHECKS: list[SecurityCheck] = [
    SecretsCheck(),
    PermissionsCheck(),
    PoisoningCheck(),
    SupplyChainCheck(),
    InjectionCheck(),
    AuthCheck(),
    ShadowCheck(),
]
