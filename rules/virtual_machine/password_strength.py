from models.security_rule import SecurityRule, Severity

def vm_password_strength_rule() -> SecurityRule:
    def check_password_strength(resource):
        # Check direct password
        password = resource.get('password')
        if password and isinstance(password, str) and len(password) < 12:
            return True
            
        # Check azure_specific password
        azure_specific = resource.get('azure_specific', {})
        azure_password = azure_specific.get('password')
        if azure_password and isinstance(azure_password, str) and len(azure_password) < 12:
            return True
            
        return False

    return SecurityRule(
        id="VM_SEC_001",
        name="VM Password Strength Check", 
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=check_password_strength,
        recommendation="Use a strong password with minimum 12 characters",
        version="1.0.0"
    )
