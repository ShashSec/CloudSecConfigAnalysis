from models.security_rule import SecurityRule, Severity

def ensure_endpoint_protection() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_008",
        name="Endpoint Protection Installation",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=lambda resource: (
            'security_profile' in resource.azure_specific and
            resource.azure_specific['security_profile'].get('endpoint_protection_enabled') is True
        ),
        recommendation="Install and enable endpoint protection on all VMs",
        version="1.0.0"
    )