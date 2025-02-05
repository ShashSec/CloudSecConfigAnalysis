
from models.security_rule import SecurityRule, Severity
def sql_public_network_access_rule() -> SecurityRule:
    """
    10.7 Ensure Public Network Access is Disabled (Manual)
    """
    return SecurityRule(
        id="SQL_DB_007",
        name="SQL Server Public Network Access Disabled Check",
        severity=Severity.HIGH,
        resource_type="database",
        condition=lambda resource: (
            not resource.get('public_network_access_enabled', True) or
            not resource.get('azure_specific', {}).get('public_network_access_enabled', True)
        ),
        recommendation="Disable public network access and use private endpoints for SQL Server access",
        version="1.0.0"
    )