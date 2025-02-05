from typing import Dict, Any
from models.security_rule import SecurityRule, Severity

def storage_network_rules_rule() -> SecurityRule:
    """
    2.2.1.2 Ensure Network Access Rules are set to Deny-by-default (Automated)
    """
    return SecurityRule(
        id="STG_SEC_005",
        name="Storage Account Network Rules Check",
        severity=Severity.HIGH,
        resource_type="storage_account",
        condition=lambda resource: (
            resource.get('default_network_access', 'Allow') == 'Deny' or
            resource.get('azure_specific', {}).get('networkAcls', {}).get('defaultAction') == 'Deny'
        ),
        recommendation="Set default network access rules to Deny and explicitly allow required networks",
        version="1.0.0"
    )