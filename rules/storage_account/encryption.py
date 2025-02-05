from models.security_rule import SecurityRule, Severity
from models.resource import Resource


def storage_encryption_rule() -> SecurityRule:
    return SecurityRule(
        id="STG_SEC_001",
        name="Storage Account Encryption Check",
        severity=Severity.HIGH,
        resource_type="storage_account",
        condition=lambda resource: not (resource.encryption or resource.azure_specific.encryption),
        recommendation="Enable encryption for storage accounts to protect data at rest",
        version="1.0.0"
    )