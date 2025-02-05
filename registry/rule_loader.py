import importlib
import inspect
from typing import List
from models.security_rule import SecurityRule
from .rule_registry import SecurityRuleRegistry

class RuleLoader:
    def __init__(self, registry: SecurityRuleRegistry):
        self.registry = registry

    def load_rules_from_module(self, module_path: str) -> None:
        """Load all rules from a given module path."""
        try:
            module = importlib.import_module(module_path)
            for name, obj in inspect.getmembers(module):
                if (inspect.isfunction(obj) and 
                    name.endswith('_rule') and 
                    not name.startswith('_')):
                    rule = obj()
                    if isinstance(rule, SecurityRule):
                        self.registry.register_rule(rule)
        except ImportError as e:
            print(f"Error loading module {module_path}: {e}")

    def load_all_rules(self) -> None:
        """Load all rules from all resource type modules."""
        rule_modules = [
            "rules.virtual_machine.password_strength",
            "rules.virtual_machine.encryption",
            "rules.virtual_machine.open_ports",
            "rules.storage_account.encryption",
            "rules.storage_account.replication"
        ]
        
        for module_path in rule_modules:
            self.load_rules_from_module(module_path)