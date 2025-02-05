from models.security_rule import SecurityRule, Severity

def vm_encryption_rule() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_002",
        name="VM Disk Encryption Check",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=lambda resource: (
            resource.azure_specific.has_property('encryption') and
            not resource.azure_specific.get_property('encryption')
        ),
        recommendation="Enable disk encryption for virtual machines",
        version="1.0.0"
    )