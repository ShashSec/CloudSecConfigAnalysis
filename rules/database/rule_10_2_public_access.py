from models.security_rule import SecurityRule, Severity
from dataclasses import dataclass
from typing import Dict, Any
from enum import Enum

def sql_public_access_rule() -> SecurityRule:
    """
    10.2 Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) (Automated)
    """
    return SecurityRule(
        id="SQL_DB_002",
        name="SQL Server Public Network Access Check",
        severity=Severity.HIGH,
        resource_type="database",
        condition=lambda resource: not (
            resource.get('public_access_enabled', False) or 
            resource.get('azure_specific', {}).get('public_access_enabled', False) or
            resource.get('allow_all_ips', False) or
            resource.get('azure_specific', {}).get('allow_all_ips', False)
        ),
        recommendation="Restrict public network access to SQL Server and configure specific IP ranges or VNet rules",
        version="1.0.0"
    )