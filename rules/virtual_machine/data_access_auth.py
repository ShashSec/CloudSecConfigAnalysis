from models.security_rule import SecurityRule, Severity

def ensure_data_access_auth() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_006",
        name="Data Access Authentication Mode",
        severity=Severity.MEDIUM,
        resource_type="virtual_machine",
        condition=lambda resource: (
            'data_access_auth_mode' in resource.azure_specific and
            resource.azure_specific['data_access_auth_mode'] == 'Enabled'
        ),
        recommendation="Enable Data Access Authentication Mode for secure disk access",
        version="1.0.0"
    )