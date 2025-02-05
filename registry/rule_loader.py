import importlib
import inspect
from typing import List
from models.security_rule import SecurityRule
from .rule_registry import SecurityRuleRegistry
import os
from pathlib import Path

class RuleLoader:
    def __init__(self, registry):
        self.registry = registry
        self.rules_dir = Path(__file__).parent.parent / 'rules'

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
        # Get all directory names under rules/ as resource types
        resource_types = [d.name for d in self.rules_dir.iterdir() 
                         if d.is_dir() and not d.name.startswith('__')]
        
        for resource_type in resource_types:
            # Get all .py files in the resource type directory
            rule_dir = self.rules_dir / resource_type
            rule_files = [f.stem for f in rule_dir.glob('*.py') 
                         if f.is_file() and not f.name.startswith('__')]
            
            for rule_file in rule_files:
                module_path = f"rules.{resource_type}.{rule_file}"
                self.load_rules_from_module(module_path)