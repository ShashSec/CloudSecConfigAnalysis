from models.security_rule import SecurityRule, Severity

def ensure_vhd_encryption() -> SecurityRule:
    def check_vhd_encryption(resource):
        # Check direct property
        direct_encryption = resource.get('vhd_encryption', {})
        if not direct_encryption.get('enabled', False):
            return True
            
        # Check azure_specific property    
        azure_specific = resource.get('azure_specific', {})
        azure_encryption = azure_specific.get('vhd_encryption', {})
        if not azure_encryption.get('enabled', False):
            return True
            
        return False

    return SecurityRule(
        id="VM_SEC_009",
        name="VHD Encryption Status", 
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=check_vhd_encryption,
        recommendation="Enable encryption for all VHD files",
        version="1.0.0"
    )