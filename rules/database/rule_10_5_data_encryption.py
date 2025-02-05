from cloudsecconfiganalysis.rules import SecurityRule, Severity
from typing import Dict, Any


def sql_data_encryption_rule() -> SecurityRule:
    """
    10.5 Ensure that 'Data encryption' is set to 'On' on a SQL Database (Automated)
    """
    return SecurityRule(
        id="SQL_DB_005",
        name="SQL Database Encryption Check",
        severity=Severity.HIGH,
        resource_type="database",
        condition=lambda resource: (
            resource.get('data_encryption_enabled', False) or
            resource.get('azure_specific', {}).get('data_encryption_enabled', False)
        ),
        recommendation="Enable data encryption for all SQL Databases",
        version="1.0.0"
    )