from typing import Dict, List, Set
from models.security_rule import SecurityRule
import importlib
import pkgutil
import rules

class SecurityRuleRegistry:
    def __init__(self):
        self.rules: Dict[str, SecurityRule] = {}
        self.rules_by_resource_type: Dict[str, Set[str]] = {}

    def register_rule(self, rule: SecurityRule) -> None:
        self.rules[rule.id] = rule
        
        if rule.resource_type not in self.rules_by_resource_type:
            self.rules_by_resource_type[rule.resource_type] = set()
        
        self.rules_by_resource_type[rule.resource_type].add(rule.id)

    def get_rules_by_resource_type(self, resource_type: str) -> List[SecurityRule]:
        rule_ids = self.rules_by_resource_type.get(resource_type, set())
        return [self.rules[rule_id] for rule_id in rule_ids]

    def get_all_rules(self) -> List[SecurityRule]:
        return list(self.rules.values())