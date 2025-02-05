from enum import Enum
from typing import Dict, Any
from datetime import datetime, timedelta
from models.security_rule import SecurityRule, Severity

def storage_sas_expiry_rule() -> SecurityRule:
    """
    2.1.1.2 Ensure that shared access signature (SAS) tokens expire within an hour (Manual)
    """
    return SecurityRule(
        id="STG_SEC_002",
        name="Storage Account SAS Token Expiry Check",
        severity=Severity.HIGH,
        resource_type="storage_account",
        condition=lambda resource: (
            resource.get('sas_expiry_hours', 24) <= 1 or
            resource.get('azure_specific', {}).get('sas_expiry_hours', 24) <= 1
        ),
        recommendation="Configure SAS tokens to expire within one hour to minimize security risks",
        version="1.0.0"
    )