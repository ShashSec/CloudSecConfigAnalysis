from models.security_rule import SecurityRule, Severity
from models.resource import Resource

def vm_encryption_rule() -> SecurityRule:
    def check_encryption(resource: Resource) -> bool:
        # Check direct encryption property
        if not resource.get('encryption', False):
            return True
            
        # Check azure_specific encryption
        azure_specific = resource.get('azure_specific', {})
        if not azure_specific.get('disk_encryption', {}).get('enabled', False):
            return True
            
        return False

    return SecurityRule(
        id="VM_SEC_002",
        name="VM Disk Encryption Check",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=check_encryption,
        recommendation="Enable disk encryption for virtual machines",
        version="1.0.0"
    )



