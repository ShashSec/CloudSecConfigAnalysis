from models.security_rule import SecurityRule, Severity

def ensure_bastion_host_exists() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_001",
        name="Azure Bastion Host Existence",
        severity=Severity.HIGH,
        resource_type="virtual_machine",
        condition=lambda resource: (
            'bastion_host' in resource.azure_specific and
            resource.azure_specific['bastion_host'] is not None
        ),
        recommendation="Deploy an Azure Bastion host to enable secure remote access",
        version="1.0.0"
    )