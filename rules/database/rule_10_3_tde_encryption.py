from models.security_rule import SecurityRule, Severity
from dataclasses import dataclass
from typing import Dict, Any
from enum import Enum

def sql_tde_encryption_rule() -> SecurityRule:
    """
    10.3 Ensure SQL server's TDE protector is encrypted with Customer-managed key (Automated)
    """
    return SecurityRule(
        id="SQL_DB_003",
        name="SQL Server TDE Customer Managed Key Check",
        severity=Severity.HIGH,
        resource_type="database",
        condition=lambda resource: (
            (resource.get('tde_enabled', False) or 
             resource.get('azure_specific', {}).get('tde_enabled', False)) and
            (resource.get('using_customer_managed_key', False) or 
             resource.get('azure_specific', {}).get('using_customer_managed_key', False))
        ),
        recommendation="Enable Transparent Data Encryption with customer-managed keys for SQL Server",
        version="1.0.0"
    )