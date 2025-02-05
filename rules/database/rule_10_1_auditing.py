from dataclasses import dataclass
from typing import Dict, Any
from enum import Enum
from models.security_rule import SecurityRule
from models.resource import Resource
from models.security_rule import Severity

def sql_auditing_rule() -> SecurityRule:
    """
    10.1 Ensure that 'Auditing' is set to 'On' (Automated)
    """
    def check_auditing(resource: Resource) -> bool:
        # Check direct property
        if resource.has_property('auditing_enabled'):
            if not resource.get('auditing_enabled'):
                return True
                
        # Check azure_specific property
        azure_specific = resource.azure_specific
        if not azure_specific.get('auditing_enabled', False):
            return True
                
        return False

    return SecurityRule(
        id="SQL_DB_001",
        name="SQL Server Auditing Enabled",
        severity=Severity.HIGH,
        resource_type="database",
        condition=check_auditing,
        recommendation="Enable auditing on SQL Server to track database events and maintain audit logs",
        version="1.0.0"
    )
