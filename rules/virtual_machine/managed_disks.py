from models.security_rule import SecurityRule, Severity

def ensure_managed_disks() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_002",
        name="Managed Disks Usage",
        severity=Severity.MEDIUM,
        resource_type="virtual_machine",
        condition=lambda resource: (
            'storage_profile' in resource.azure_specific and
            resource.azure_specific['storage_profile'].get('osDisk', {}).get('managedDisk') is not None
        ),
        recommendation="Migrate blob-based VHDs to Managed Disks for enhanced security and manageability",
        version="1.0.0"
    )



