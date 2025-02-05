from models.security_rule import SecurityRule, Severity
def storage_private_endpoints_rule() -> SecurityRule:
    """
    2.2.2.1 Ensure Private Endpoints are used to access Storage Account (Automated)
    """
    return SecurityRule(
        id="STG_SEC_006",
        name="Storage Account Private Endpoints Check",
        severity=Severity.HIGH,
        resource_type="storage_account",
        condition=lambda resource: (
            resource.get('private_endpoints_enabled', False) or
            resource.get('azure_specific', {}).get('privateEndpointConnections', [])
        ),
        recommendation="Configure private endpoints for secure access to storage account",
        version="1.0.0"
    )