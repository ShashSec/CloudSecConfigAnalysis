from models.security_rule import SecurityRule, Severity
def ensure_os_disk_encryption() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_003",
        name="OS Disk Encryption with CMK",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=lambda resource: (
            'disk_encryption' in resource.azure_specific and
            resource.azure_specific['disk_encryption'].get('type') == 'CMK' and
            resource.azure_specific['disk_encryption'].get('enabled') is True
        ),
        recommendation="Enable disk encryption using Customer Managed Keys for OS disks",
        version="1.0.0"
    )