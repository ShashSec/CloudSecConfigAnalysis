from typing import Dict, Any
from models.security_rule import SecurityRule, Severity

class RuleResult:
    def __init__(self, status: bool, message: str):
        self.status = status
        self.message = message

def storage_public_access_rule() -> SecurityRule:
    """
    2.2.1.1 Ensure public network access is Disabled (Automated)
    """
    return SecurityRule(
        id="STG_SEC_004",
        name="Storage Account Public Access Check",
        severity=Severity.HIGH,
        resource_type="storage_account",
        condition=lambda resource: not (
            resource.get('public_network_access', True) or
            resource.get('azure_specific', {}).get('public_network_access', True)
        ),
        recommendation="Disable public network access to prevent exposure to internet",
        version="1.0.0"
    )