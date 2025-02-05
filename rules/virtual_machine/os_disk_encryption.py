from models.security_rule import SecurityRule, Severity
def ensure_os_disk_encryption() -> SecurityRule:
    def check_disk_encryption(resource):
        # Get azure_specific settings
        azure_specific = resource.get('azure_specific', {})
        disk_encryption = azure_specific.get('disk_encryption', {})
        
        # Check if encryption is disabled or not CMK
        if not disk_encryption.get('enabled', False):
            return True
            
        if disk_encryption.get('type') != 'CMK':
            return True
            
        return False

    return SecurityRule(
        id="VM_SEC_003",
        name="OS Disk Encryption with CMK",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=check_disk_encryption,
        recommendation="Enable disk encryption using Customer Managed Keys for OS disks",
        version="1.0.0"
    )