from typing import Dict, Any
from models.security_rule import SecurityRule, Severity

def storage_mmk_encryption_rule() -> SecurityRule:
    """
    2.1.2.1.1 Ensure Critical Data is Encrypted with Microsoft Managed Keys (MMK) (Manual)
    
    Description:
    Microsoft Managed Keys (MMK) provides a low overhead method of encrypting data at rest 
    and implementing encryption key management.
    
    Rationale:
    The encryption of data at rest is a foundational component of data security. Data 
    without encryption is easily compromised through loss or theft.
    """
    return SecurityRule(
        id="STG_SEC_007",
        name="Storage Account Microsoft Managed Keys Encryption Check",
        severity=Severity.HIGH,
        resource_type="storage_account",
        condition=lambda resource: (
            # Check if encryption is enabled with Microsoft Managed Keys
            resource.get('encryption_type') == 'Microsoft.Storage' or
            resource.get('azure_specific', {}).get('encryption', {}).get('keySource') == 'Microsoft.Storage'
        ),
        recommendation="Enable encryption with Microsoft Managed Keys (MMK) for data at rest",
        version="1.0.0"
    )