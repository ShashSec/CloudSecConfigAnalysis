from dataclasses import dataclass
from typing import Dict, Any
from enum import Enum
from models.security_rule import SecurityRule, Severity

def sql_auditing_rule() -> SecurityRule:
    """
    10.1 Ensure that 'Auditing' is set to 'On' (Automated)
    """
    return SecurityRule(
        id="SQL_DB_001",
        name="SQL Server Auditing Enabled",
        severity=Severity.HIGH,
        resource_type="database",
        condition=lambda resource: (
            resource.get('auditing_enabled', False) or
            resource.get('azure_specific', {}).get('auditing_enabled', False)
        ),
        recommendation="Enable auditing on SQL Server to track database events and maintain audit logs",
        version="1.0.0"
    )
