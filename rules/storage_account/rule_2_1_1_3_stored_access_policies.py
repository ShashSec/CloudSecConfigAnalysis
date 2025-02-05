from typing import Dict, Any
from models.security_rule import SecurityRule, Severity

def storage_access_policy_rule() -> SecurityRule:
    """
    2.1.1.3 Ensure stored access policies (SAP) are used when generating SAS tokens (Manual)
    """
    return SecurityRule(
        id="STG_SEC_003",
        name="Storage Account Stored Access Policy Check",
        severity=Severity.MEDIUM,
        resource_type="storage_account",
        condition=lambda resource: (
            resource.get('stored_access_policy_enabled', False) or
            resource.get('azure_specific', {}).get('stored_access_policy_enabled', False)
        ),
        recommendation="Use stored access policies (SAP) for SAS tokens to enable centralized management",
        version="1.0.0"
    )
