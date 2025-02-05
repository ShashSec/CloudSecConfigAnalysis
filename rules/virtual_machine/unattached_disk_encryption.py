from models.security_rule import SecurityRule, Severity

def ensure_unattached_disk_encryption() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_004",
        name="Unattached Disk Encryption",
        severity=Severity.HIGH,
        resource_type="disk",
        condition=lambda resource: (
            'disk_state' in resource.azure_specific and
            resource.azure_specific['disk_state'] == 'Unattached' and
            resource.azure_specific.get('encryption_settings', {}).get('enabled') is True
        ),
        recommendation="Enable encryption for all unattached disks",
        version="1.0.0"
    )