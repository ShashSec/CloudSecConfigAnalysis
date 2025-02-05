
from models.security_rule import SecurityRule, Severity
def ensure_trusted_launch() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_011",
        name="Trusted Launch Configuration",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=lambda resource: (
            'security_profile' in resource.azure_specific and
            resource.azure_specific['security_profile'].get('secure_boot_enabled') is True and
            resource.azure_specific['security_profile'].get('vtpm_enabled') is True
        ),
        recommendation="Enable Trusted Launch with Secure Boot and vTPM for supported VMs",
        version="1.0.0"
    )