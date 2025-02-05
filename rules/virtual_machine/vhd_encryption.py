from models.security_rule import SecurityRule, Severity

def ensure_vhd_encryption() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_009",
        name="VHD Encryption Status",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=lambda resource: (
            'vhd_encryption' in resource.azure_specific and
            resource.azure_specific['vhd_encryption'].get('enabled') is True
        ),
        recommendation="Enable encryption for all VHD files",
        version="1.0.0"
    )