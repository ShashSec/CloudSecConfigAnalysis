from models.security_rule import SecurityRule, Severity

def sql_audit_retention_rule() -> SecurityRule:
    """
    10.6 Ensure that 'Auditing' Retention is 'greater than 90 days' (Automated)
    """
    return SecurityRule(
        id="SQL_DB_006",
        name="SQL Server Audit Retention Check",
        severity=Severity.MEDIUM,
        resource_type="database",
        condition=lambda resource: (
            resource.get('audit_retention_days', 0) >= 90 or
            resource.get('azure_specific', {}).get('audit_retention_days', 0) >= 90
        ),
        recommendation="Configure audit log retention for at least 90 days",
        version="1.0.0"
    )