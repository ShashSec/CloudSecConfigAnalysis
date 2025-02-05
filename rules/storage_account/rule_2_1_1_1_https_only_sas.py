from enum import Enum
from typing import Dict, Any
from models.security_rule import SecurityRule, Severity

def storage_https_only_sas_rule() -> SecurityRule:
    """
    2.1.1.1 Ensure 'Allowed Protocols' for shared access signature (SAS) tokens 
    is set to 'HTTPS Only' (Manual)
    """
    return SecurityRule(
        id="STG_SEC_001",
        name="Storage Account HTTPS Only SAS Check",
        severity=Severity.HIGH,
        resource_type="storage_account",
        condition=lambda resource: (
            resource.get('https_only', False) or
            resource.get('azure_specific', {}).get('sasPolicy', {}).get('sasProtocol') == 'Https'
        ),
        recommendation="Configure SAS tokens to use HTTPS only to prevent unauthorized access",
        version="1.0.0"
    )