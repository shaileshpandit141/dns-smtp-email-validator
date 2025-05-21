from typing import TypedDict


class EmailError(TypedDict, total=False):
    """Type for API error responses"""

    email: list[str]
    code: str
