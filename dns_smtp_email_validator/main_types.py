from typing import Any, Dict, List, Optional, TypedDict

class ErrorsFieldType(TypedDict):
    """Type for API error responses"""
    field: str
    code: str
    message: str
    details: Optional[Dict[str, Any]]


ErrorsType = List[ErrorsFieldType]
