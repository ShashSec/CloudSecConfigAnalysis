from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class Resource:
    name: str
    type: str
    properties: Dict[str, Any]
    
    @property
    def azure_specific(self):
        """Get azure_specific properties as an object with attribute access"""
        return ResourceProperties(self.properties.get('azure_specific', {}))
        
    def get(self, key: str, default=None):
        """Get property from resource properties"""
        return self.properties.get(key, default)

    def has_property(self, key: str) -> bool:
        """Check if property exists in root properties"""
        return key in self.properties

@dataclass
class ResourceProperties:
    """Helper class to provide attribute-style access to properties"""
    properties: Dict[str, Any]
    
    def __getattr__(self, name):
        return self.properties.get(name)
        
    def get(self, key: str, default=None):
        return self.properties.get(key, default)