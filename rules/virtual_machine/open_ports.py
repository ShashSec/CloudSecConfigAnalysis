from models.security_rule import SecurityRule, Severity
from models.resource import Resource

def vm_open_ports_rule() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_003",
        name="VM Open Ports Check",
        severity=Severity.MEDIUM,
        resource_type="virtual_machine",
        condition=lambda resource: (
            resource.open_ports is not None and
            any(port < 1024 or port == 8080 for port in resource.open_ports)
        ),
        recommendation="Review and restrict open ports. Avoid using well-known ports unless necessary",
        version="1.0.0"
    )