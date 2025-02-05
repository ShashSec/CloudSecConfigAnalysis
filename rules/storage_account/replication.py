from models.security_rule import SecurityRule, Severity

def storage_replication_rule() -> SecurityRule:
    return SecurityRule(
        id="STG_SEC_002",
        name="Storage Account Replication Check",
        severity=Severity.MEDIUM,
        resource_type="storage_account",
        condition=lambda resource: (
            'replication' in resource.azure_specific and
            resource.azure_specific['replication'] == "LRS"
        ),
        recommendation="Use GRS or RA-GRS for critical storage accounts",
        version="1.0.0"
    )