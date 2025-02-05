from models.security_rule import SecurityRule, Severity
from typing import Dict


def ensure_disk_access_restriction() -> SecurityRule:
    return SecurityRule(
        id="VM_SEC_005",
        name="Disk Network Access Restriction",
        severity=Severity.HIGH,
        resource_type="disk",
        condition=lambda resource: (
            'network_access_policy' in resource.azure_specific and
            resource.azure_specific['network_access_policy'] != 'AllowAll'
        ),
        recommendation="Disable public network access for disk resources",
        version="1.0.0"
    )