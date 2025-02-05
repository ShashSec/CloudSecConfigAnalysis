from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class Resource:
    # Required fields
    type: str
    name: str
    
    # Dynamic properties stored in a dictionary
    properties: Dict[str, Any] = field(default_factory=dict)
    azure_specific: Dict[str, Any] = field(default_factory=dict)

    def get_property(self, key: str, default: Any = None) -> Any:
        """Safely get a property value."""
        return self.properties.get(key, default)

    def has_property(self, key: str) -> bool:
        """Check if a property exists."""
        return key in self.properties