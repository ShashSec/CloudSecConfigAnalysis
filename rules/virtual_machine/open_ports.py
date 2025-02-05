from models.security_rule import SecurityRule, Severity
from models.resource import Resource

def vm_open_ports_rule() -> SecurityRule:
    def check_open_ports(resource: Resource) -> bool:
        # Check direct open_ports
        direct_ports = resource.get('open_ports', [])
        if any(port < 1024 or port == 8080 for port in direct_ports):
            return True
            
        # Check azure_specific ports
        azure_specific = resource.get('azure_specific', {})
        azure_ports = azure_specific.get('open_ports', [])
        if any(port < 1024 or port == 8080 for port in azure_ports):
            return True
            
        return False

    return SecurityRule(
        id="VM_SEC_003",
        name="VM Open Ports Check",
        severity=Severity.MEDIUM,
        resource_type="virtual_machine",
        condition=check_open_ports,
        recommendation="Review and restrict open ports. Avoid using well-known ports unless necessary",
        version="1.0.0"
    )