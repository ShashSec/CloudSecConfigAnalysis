from dataclasses import dataclass
from typing import List, Dict
import json
import logging
from enum import Enum

logger = logging.getLogger(__name__)

class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class AIFinding:
    rule_id: str
    resource_name: str
    resource_type: str
    severity: str  # Changed from Severity enum to str
    description: str
    recommendation: str

    @classmethod
    def from_dict(cls, data: Dict) -> 'AIFinding':
        return cls(
            rule_id=data.get('rule_id', ''),
            resource_name=data.get('resource_name', ''),
            resource_type=data.get('resource_type', ''),
            severity=data.get('severity', 'MEDIUM'),  # Get string value directly
            description=data.get('description', ''),
            recommendation=data.get('recommendation', '')
        )

class AIFindings:
    def __init__(self, raw_json: str):
        self.findings: List[AIFinding] = []
        self.parse_json(raw_json)

    def parse_json(self, raw_json: str) -> None:
        try:
            data = json.loads(raw_json)
            if isinstance(data, list):
                findings_list = data
            elif isinstance(data, dict):
                findings_list = [data]
            else:
                raise ValueError("Invalid JSON structure")

            for finding_data in findings_list:
                try:
                    finding = AIFinding.from_dict(finding_data)
                    self.findings.append(finding)
                except Exception as e:
                    logger.error(f"Error parsing finding: {e}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
        except Exception as e:
            logger.error(f"Error processing findings: {e}")