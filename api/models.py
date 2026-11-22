from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

# Literal = only these exact values are allowed. Anything else gets a 422 error.
Rule = Literal["brute_force", "impossible_travel", "large_upload"]
Severity = Literal["high", "critical"]


class Alert(BaseModel):
    alert_id: UUID
    detected_at: datetime
    event_timestamp: datetime
    user_id: str
    rule: Rule
    severity: Severity
    details: str
    event_id: UUID


class AlertPage(BaseModel):
    items: list[Alert]
    next_cursor: str | None  # pass this back to get the next page; None = last page


class RuleCount(BaseModel):
    rule: Rule
    severity: Severity
    count: int
