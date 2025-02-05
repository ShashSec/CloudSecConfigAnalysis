from cloudsecconfiganalysis.rules import SecurityRule, Severity


def sql_entra_auth_rule() -> SecurityRule:
    """
    10.4 Ensure that Microsoft Entra authentication is Configured for SQL Servers (Automated)
    """
    return SecurityRule(
        id="SQL_DB_004",
        name="SQL Server Microsoft Entra Authentication Check",
        severity=Severity.HIGH,
        resource_type="sql_server",
        condition=lambda resource: (
            resource.get('entra_auth_enabled', False) or
            resource.get('azure_specific', {}).get('entra_auth_enabled', False)
        ),
        recommendation="Configure Microsoft Entra authentication for centralized identity management",
        version="1.0.0"
    )