from dataclasses import dataclass
from typing import Callable
from enum import Enum
from .resource import Resource

class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class SecurityRule:
    id: str
    name: str
    severity: Severity
    resource_type: str
    condition: Callable[[Resource], bool]
    recommendation: str
    version: str

@dataclass
class SecurityFinding:
    rule_id: str
    resource_name: str
    resource_type: str
    severity: str
    description: str
    recommendation: str