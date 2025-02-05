from typing import List, Optional
import asyncio
from models.resource import Resource
from models.security_rule import SecurityRule, SecurityFinding
from registry.rule_registry import SecurityRuleRegistry

class SecurityAnalysisEngine:
    def __init__(self, registry: SecurityRuleRegistry):
        self.registry = registry

    async def analyze_resource(self, resource: Resource) -> List[SecurityFinding]:
        """Analyze a single resource against all applicable rules."""
        rules = self.registry.get_rules_by_resource_type(resource.type)
        return await self._execute_rules(resource, rules)

    async def _execute_rules(self, resource: Resource, rules: List[SecurityRule]) -> List[SecurityFinding]:
        """Execute all rules for a resource in parallel."""
        tasks = [
            self._execute_rule_with_timeout(resource, rule)
            for rule in rules
        ]
        findings = await asyncio.gather(*tasks)
        return [f for f in findings if f is not None]

    async def _execute_rule_with_timeout(
        self, resource: Resource, rule: SecurityRule, timeout: float = 5.0
    ) -> Optional[SecurityFinding]:
        """Execute a single rule with timeout."""
        try:
            async with asyncio.timeout(timeout):
                if rule.condition(resource):
                    return SecurityFinding(
                        rule_id=rule.id,
                        resource_name=resource.name,
                        resource_type=resource.type,
                        severity=rule.severity.value,
                        description=f"Resource {resource.name} violates rule {rule.name}",
                        recommendation=rule.recommendation
                    )
                return None
        except asyncio.TimeoutError:
            print(f"Rule {rule.id} timed out for resource {resource.name}")
            return None
        except Exception as e:
            print(f"Error executing rule {rule.id} for resource {resource.name}: {e}")
            return None