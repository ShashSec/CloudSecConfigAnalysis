from models.security_rule import SecurityRule, Severity

def vm_password_strength_rule() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_001",
        name="VM Password Strength Check",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=lambda resource: (
            (resource.has_property('password') or resource.azure_specific.has_property('password')) and 
            isinstance(resource.get_property('password') or resource.azure_specific.get_property('password'), str) and
            len(resource.get_property('password') or resource.azure_specific.get_property('password')) < 12
        ),
        recommendation="Use a strong password with minimum 12 characters",
        version="1.0.0"
    )
