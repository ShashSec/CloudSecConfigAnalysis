from models.security_rule import SecurityRule, Severity

def ensure_unattached_disk_encryption() -> SecurityRule:
    def check_disk_encryption(resource):
        # Get azure_specific settings
        azure_specific = resource.get('azure_specific', {})
        disk_state = azure_specific.get('disk_state')
        encryption_settings = azure_specific.get('encryption_settings', {})

        # Return True if violation found (unattached disk without encryption)
        if disk_state == 'Unattached':
            return not encryption_settings.get('enabled', False)
            
        return False

    return SecurityRule(
        id="VM_SEC_004", 
        name="Unattached Disk Encryption",
        severity=Severity.HIGH,
        resource_type="disk",
        condition=check_disk_encryption,
        recommendation="Enable encryption for all unattached disks",
        version="1.0.0"
    )