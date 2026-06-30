"""Security checks registry. Each check implements the SecurityCheck protocol."""

from typing import Protocol

from mcp_guard.types import ScanTarget, Finding


class SecurityCheck(Protocol):
    id: str
    name: str
    owasp: str

    def run(self, target: ScanTarget) -> list[Finding]: ...


# Import and register all checks
from mcp_guard.checks.secrets import SecretsCheck
from mcp_guard.checks.injection import InjectionCheck
from mcp_guard.checks.permissions import PermissionsCheck
from mcp_guard.checks.poisoning import PoisoningCheck
from mcp_guard.checks.auth import AuthCheck
from mcp_guard.checks.supply_chain import SupplyChainCheck
from mcp_guard.checks.shadow import ShadowCheck

ALL_CHECKS: list = [
    SecretsCheck(),
    PermissionsCheck(),
    PoisoningCheck(),
    SupplyChainCheck(),
    InjectionCheck(),
    AuthCheck(),
    ShadowCheck(),
]
